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
use std::io;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Output;

const CLIENT_ENV: &str = "REVERIE_DBI_CLIENT";
const DYNAMORIO_ENV: &str = "DYNAMORIO_HOME";
const DYNAMORIO_DIR_ENV: &str = "DynamoRIO_DIR";
const SUMMARY_ENV: &str = "REVERIE_DBI_SUMMARY";
const BINPRM_BUF_SIZE: usize = 256;

/// Launches Linux programs under the Reverie DynamoRIO client.
///
/// The native client is built separately by
/// `reverie-dbi/scripts/build-client.sh`. Set [`REVERIE_DBI_CLIENT`] to that
/// script's output, or build it in this Reverie workspace's default target
/// directory. [`DYNAMORIO_HOME`] must identify a built DynamoRIO source tree,
/// build directory, or install directory. Set `REVERIE_DBI_SUMMARY=1` to print
/// instrumentation totals after the guest exits.
///
/// [`REVERIE_DBI_CLIENT`]: https://github.com/rrnewton/reverie/tree/main/reverie-dbi
/// [`DYNAMORIO_HOME`]: https://dynamorio.org/page_deploy.html
#[derive(Clone, Debug)]
pub struct DbiRunner {
    drrun: PathBuf,
    client: PathBuf,
    summary: bool,
}

impl DbiRunner {
    /// Resolves DynamoRIO and the Reverie DBI client from the environment.
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
        require_file(&client, "Reverie DBI client")?;
        Ok(Self {
            drrun,
            client,
            summary: false,
        })
    }

    /// Enables or disables the instrumentation summary written at process exit.
    pub fn summary(mut self, enabled: bool) -> Self {
        self.summary = enabled;
        self
    }

    /// Runs `guest` with inherited standard streams and waits for it to exit.
    pub fn status(&self, guest: &Command) -> io::Result<ExitStatus> {
        self.command(guest, None).status()
    }

    /// Runs `guest` with an exact environment instead of inheriting the launcher environment.
    pub fn status_with_environment(
        &self,
        guest: &Command,
        environment: &BTreeMap<OsString, OsString>,
    ) -> io::Result<ExitStatus> {
        self.command(guest, Some(environment)).status()
    }

    /// Runs `guest` and captures its standard output and standard error.
    pub fn output(&self, guest: &Command) -> io::Result<Output> {
        self.command(guest, None).output()
    }

    /// Captures `guest` output while supplying an exact guest environment.
    pub fn output_with_environment(
        &self,
        guest: &Command,
        environment: &BTreeMap<OsString, OsString>,
    ) -> io::Result<Output> {
        self.command(guest, Some(environment)).output()
    }

    fn command(
        &self,
        guest: &Command,
        environment: Option<&BTreeMap<OsString, OsString>>,
    ) -> Command {
        let mut command = Command::new(&self.drrun);
        command.arg("-disable_rseq").arg("-c").arg(&self.client);
        if self.summary {
            command.arg("-summary");
        }
        command.arg("--");

        if let Some((interpreter, interpreter_args)) = shebang(guest.get_program()) {
            command
                .arg(interpreter)
                .args(interpreter_args)
                .arg(guest.get_program());
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
        // SAFETY: personality(2) is async-signal-safe and the closure captures no
        // process state. The flag survives both the drrun and guest execs.
        unsafe {
            command.pre_exec(|| {
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
        .expect("reverie-dbi must be inside its workspace")
        .join("target");
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os(CLIENT_ENV) {
        candidates.push(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(path).join("reverie-dbi-native/libreverie_dbi_client.so"));
    }
    candidates.push(workspace_target.join("reverie-dbi-native/libreverie_dbi_client.so"));

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Reverie DBI client was not found; set REVERIE_DBI_CLIENT to libreverie_dbi_client.so or run reverie-dbi/scripts/build-client.sh",
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
    use super::*;

    fn runner() -> DbiRunner {
        DbiRunner {
            drrun: PathBuf::from("/opt/dynamorio/bin64/drrun"),
            client: PathBuf::from("/opt/reverie/libreverie_dbi_client.so"),
            summary: false,
        }
    }

    #[test]
    fn wraps_guest_program_arguments_directory_and_environment() {
        let mut guest = Command::new("/bin/echo");
        guest
            .args(["hello", "dbi"])
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
                "-disable_rseq",
                "-c",
                "/opt/reverie/libreverie_dbi_client.so",
                "--",
                "/bin/echo",
                "hello",
                "dbi",
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
                OsStr::new("-disable_rseq"),
                OsStr::new("-c"),
                OsStr::new("/opt/reverie/libreverie_dbi_client.so"),
                OsStr::new("--"),
                OsStr::new("/usr/bin/env"),
                OsStr::new("bash"),
                script.as_os_str(),
                OsStr::new("argument"),
            ]
        );
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
}
