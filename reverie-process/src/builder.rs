/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use syscalls::Errno;

use super::seccomp;
use super::util::to_cstring;
use super::util::CStringArray;
use super::Command;
use super::Container;
use super::Mount;
use super::Namespace;
use super::PtyChild;
use super::Stdio;

impl Command {
    /// Constructs a new `Command` for launching the program at path `program`,
    /// with the following default configuration:
    ///
    /// * No arguments to the program
    /// * Inherit the current process's environment
    /// * Inherit the current process's working directory
    /// * Inherit stdin/stdout/stderr for `spawn` or `status`, but create pipes
    ///   for `output`
    ///
    /// Builder methods are provided to change these defaults and
    /// otherwise configure the process.
    ///
    /// If `program` is not an absolute path, the `PATH` will be searched in an
    /// OS-defined way.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::Command;
    /// let command = Command::new("sh");
    /// ```
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        let program = to_cstring(program);

        let mut args = CStringArray::with_capacity(1);
        args.push(program.clone());

        Self {
            program,
            args,
            pre_exec: Vec::new(),
            container: Container::new(),
        }
    }

    /// Sets the path to the program. This can be used to override what was
    /// already set in [`Command::new`].
    ///
    /// NOTE: This also changes argument 0 to match `program`.
    pub fn program<S: AsRef<OsStr>>(&mut self, program: S) -> &mut Self {
        let cstring = to_cstring(program);
        self.program = cstring.clone();
        self.args.set(0, cstring);
        self
    }

    /// Explicitly sets the first argument. By default, this is the same as the
    /// program path and is what you want in most cases.
    pub fn arg0<S: AsRef<OsStr>>(&mut self, arg0: S) -> &mut Self {
        self.args.set(0, to_cstring(arg0));
        self
    }

    /// Gets the first argument. Unless [`Command::arg0`] was used, this returns
    /// the same string as [`Command::get_program`].
    pub fn get_arg0(&self) -> &OsStr {
        OsStr::from_bytes(self.args.get(0).to_bytes())
    }

    /// Adds an argument to pass to the program.
    ///
    /// Only one argument can be passed per use. So instead of:
    ///
    /// ```no_run
    /// reverie_process::Command::new("sh")
    ///   .arg("-C /path/to/repo");
    /// ```
    ///
    /// usage would be:
    ///
    /// ```no_run
    /// reverie_process::Command::new("sh")
    ///   .arg("-C")
    ///   .arg("/path/to/repo");
    /// ```
    ///
    /// To pass multiple arguments see [`args`].
    ///
    /// [`args`]: method@Self::args
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::Command;
    ///
    /// let command = Command::new("ls")
    ///         .arg("-l")
    ///         .arg("-a");
    /// ```
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.args.push(to_cstring(arg));
        self
    }

    /// Adds multiple arguments to pass to the program.
    ///
    /// To pass a single argument see [`arg`].
    ///
    /// [`arg`]: method@Self::arg
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::Command;
    ///
    /// let command = Command::new("ls")
    ///         .args(&["-l", "-a"]);
    /// ```
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    /// Returns an iterator of the arguments that will be passed to the program.
    ///
    /// This does not include the program name itself. It only includes the
    /// arguments specified with [`Command::arg`] and [`Command::args`].
    pub fn get_args(&self) -> impl Iterator<Item = &OsStr> {
        self.args
            .iter()
            .skip(1)
            .map(|arg| OsStr::from_bytes(arg.to_bytes()))
    }

    /// Prepends arguments to the beginning of the command. Note that arguments
    /// are prepended *after* arg0, but before the rest of the arguments.
    pub fn prepend_args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let new_args = CStringArray::with_capacity(self.args.len() + 1);
        let mut old_args = core::mem::replace(&mut self.args, new_args).into_iter();

        // Add arg0 first
        if let Some(arg0) = old_args.next() {
            self.args.push(arg0);
        }

        // Add the new arguments
        self.args(args);

        // Add the rest of the old arguments
        for arg in old_args {
            self.args.push(arg);
        }

        self
    }

    /// Inserts or updates an environment variable mapping.
    ///
    /// Note that environment variable names are case-insensitive (but
    /// case-preserving) on Windows, and case-sensitive on all other platforms.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::Command;
    ///
    /// let command = Command::new("ls")
    ///         .env("PATH", "/bin");
    /// ```
    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.container.env(key, val);
        self
    }

    /// Adds or updates multiple environment variable mappings.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::{Command, Stdio};
    /// use std::env;
    /// use std::collections::HashMap;
    ///
    /// let filtered_env : HashMap<String, String> =
    ///     env::vars().filter(|&(ref k, _)|
    ///         k == "TERM" || k == "TZ" || k == "LANG" || k == "PATH"
    ///     ).collect();
    ///
    /// let command = Command::new("printenv")
    ///         .stdin(Stdio::null())
    ///         .stdout(Stdio::inherit())
    ///         .env_clear()
    ///         .envs(&filtered_env);
    /// ```
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.container.envs(vars);
        self
    }

    /// Removes an environment variable mapping.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::Command;
    ///
    /// let command = Command::new("ls")
    ///         .env_remove("PATH");
    /// ```
    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Self {
        self.container.env_remove(key);
        self
    }

    /// Clears the entire environment map for the child process.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::Command;
    ///
    /// let command = Command::new("ls")
    ///         .env_clear();
    /// ```
    pub fn env_clear(&mut self) -> &mut Self {
        self.container.env_clear();
        self
    }

    /// Sets the working directory for the child process.
    ///
    /// # Interaction with `chroot`
    ///
    /// The working directory is set *after* the chroot is performed (if a chroot
    /// directory is specified). Thus, the path given is relative to the chroot
    /// directory. Otherwise, if no chroot directory is specified, the working
    /// directory is relative to the current working directory of the parent
    /// process at the time the child process is spawned.
    ///
    /// # Platform-specific behavior
    ///
    /// If the program path is relative (e.g., `"./script.sh"`), it's ambiguous
    /// whether it should be interpreted relative to the parent's working
    /// directory or relative to `current_dir`. The behavior in this case is
    /// platform specific and unstable, and it's recommended to use
    /// [`canonicalize`] to get an absolute program path instead.
    ///
    /// [`canonicalize`]: std::fs::canonicalize()
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::Command;
    ///
    /// let command = Command::new("ls")
    ///         .current_dir("/bin");
    /// ```
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.container.current_dir(dir);
        self
    }

    /// Sets configuration for the child process's standard input (stdin) handle.
    ///
    /// Defaults to [`Stdio::inherit`] when used with `spawn` or `status`, and
    /// defaults to [`Stdio::piped`] when used with `output`.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::{Command, Stdio};
    ///
    /// let command = Command::new("ls")
    ///         .stdin(Stdio::null());
    /// ```
    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.container.stdin(cfg);
        self
    }

    /// Sets configuration for the child process's standard output (stdout)
    /// handle.
    ///
    /// Defaults to [`Stdio::inherit`] when used with `spawn` or `status`, and
    /// defaults to [`Stdio::piped`] when used with `output`.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::{Command, Stdio};
    ///
    /// let command = Command::new("ls")
    ///         .stdout(Stdio::null());
    /// ```
    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.container.stdout(cfg);
        self
    }

    /// Sets configuration for the child process's standard error (stderr)
    /// handle.
    ///
    /// Defaults to [`Stdio::inherit`] when used with `spawn` or `status`, and
    /// defaults to [`Stdio::piped`] when used with `output`.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::{Command, Stdio};
    ///
    /// let command = Command::new("ls")
    ///         .stderr(Stdio::null());
    /// ```
    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.container.stderr(cfg);
        self
    }

    /// Changes the root directory of the calling process to the specified path.
    /// This directory will be inherited by all child processes of the calling
    /// process.
    ///
    /// Note that changing the root directory may cause the program to not be
    /// found. As such, the program path should be relative to this directory.
    pub fn chroot<P: AsRef<Path>>(&mut self, chroot: P) -> &mut Self {
        self.container.chroot(chroot);
        self
    }

    /// Unshares parts of the process execution context that are normally shared
    /// with the parent process. This is useful for executing the child process
    /// in a new namespace.
    pub fn unshare(&mut self, namespace: Namespace) -> &mut Self {
        self.container.unshare(namespace);
        self
    }

    /// Schedules a closure to be run just before the `exec` function is invoked.
    ///
    /// The closure is allowed to return an I/O error whose OS error code will be
    /// communicated back to the parent and returned as an error from when the
    /// spawn was requested.
    ///
    /// Multiple closures can be registered and they will be called in order of
    /// their registration. If a closure returns `Err` then no further closures
    /// will be called and the spawn operation will immediately return with a
    /// failure.
    ///
    /// # Safety
    ///
    /// This closure will be run in the context of the child process after a
    /// `fork`. This primarily means that any modifications made to memory on
    /// behalf of this closure will **not** be visible to the parent process.
    /// This is often a very constrained environment where normal operations like
    /// `malloc` or acquiring a mutex are not guaranteed to work (due to other
    /// threads perhaps still running when the `fork` was run).
    ///
    /// This also means that all resources such as file descriptors and
    /// memory-mapped regions got duplicated. It is your responsibility to make
    /// sure that the closure does not violate library invariants by making
    /// invalid use of these duplicates.
    ///
    /// When this closure is run, aspects such as the stdio file descriptors and
    /// working directory have successfully been changed, so output to these
    /// locations may not appear where intended.
    pub unsafe fn pre_exec<F>(&mut self, f: F) -> &mut Self
    where
        F: FnMut() -> Result<(), Errno> + Send + Sync + 'static,
    {
        self.pre_exec.push(Box::new(f));
        self
    }

    /// Returns the path to the program that was given to [`Command::new`].
    ///
    /// # Examples
    ///
    /// ```
    /// use reverie_process::Command;
    ///
    /// let cmd = Command::new("echo");
    /// assert_eq!(cmd.get_program(), "echo");
    /// ```
    pub fn get_program(&self) -> &OsStr {
        OsStr::from_bytes(self.program.to_bytes())
    }

    /// Returns the working directory for the child process.
    ///
    /// This returns None if the working directory will not be changed.
    pub fn get_current_dir(&self) -> Option<&Path> {
        self.container.get_current_dir()
    }

    /// Returns an iterator of the environment variables that will be set when
    /// the process is spawned. Note that this does not include any environment
    /// variables inherited from the parent process.
    pub fn get_envs(&self) -> impl Iterator<Item = (&OsStr, Option<&OsStr>)> {
        self.container.get_envs()
    }

    /// Returns a mapping of all environment variables that the new child process
    /// will inherit.
    pub fn get_captured_envs(&self) -> BTreeMap<OsString, OsString> {
        self.container.get_captured_envs()
    }

    /// Gets an environment variable. If the child process is to inherit this
    /// environment variable from the current process, then this returns the
    /// current process's environment variable unless it is to be overridden.
    pub fn get_env<K: AsRef<OsStr>>(&self, env: K) -> Option<Cow<OsStr>> {
        self.container.get_env(env)
    }

    /// Maps one user ID to another.
    ///
    /// Implies `Namespace::USER`.
    ///
    /// # Example
    ///
    /// This is can be used to gain `CAP_SYS_ADMIN` privileges in the user
    /// namespace by mapping the root user inside the container to the current
    /// user outside of the container.
    ///
    /// ```no_run
    /// use reverie_process::Command;
    ///
    /// let command = Command::new("ls")
    ///     .map_uid(1, unsafe { libc::getuid() });
    /// ```
    ///
    /// # Implementation
    ///
    /// This modifies `/proc/{pid}/uid_map` where `{pid}` is the PID of the child
    /// process. See [`user_namespaces(7)`] for more details.
    ///
    /// [`user_namespaces(7)`]: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
    pub fn map_uid(&mut self, inside_uid: libc::uid_t, outside_uid: libc::uid_t) -> &mut Self {
        self.container.map_uid(inside_uid, outside_uid);
        self
    }

    /// Maps potentially many user IDs inside the new user namespace to user IDs
    /// outside of the user namespace.
    ///
    /// Implies `Namespace::USER`.
    ///
    /// # Implementation
    ///
    /// This modifies `/proc/{pid}/uid_map` where `{pid}` is the PID of the child
    /// process. See [`user_namespaces(7)`] for more details.
    ///
    /// [`user_namespaces(7)`]: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
    pub fn map_uid_range(
        &mut self,
        starting_inside_uid: libc::uid_t,
        starting_outside_uid: libc::uid_t,
        count: u32,
    ) -> &mut Self {
        self.container
            .map_uid_range(starting_inside_uid, starting_outside_uid, count);
        self
    }

    /// Convience function for mapping root (inside the container) to the current
    /// user ID (outside the container). This is useful for gaining new
    /// capabilities inside the container, such as being able to mount file
    /// systems.
    ///
    /// Implies `Namespace::USER`.
    ///
    /// This is the same as:
    /// ```no_run
    /// use reverie_process::Command;
    ///
    /// let command = Command::new("ls")
    ///     .map_uid(0, unsafe { libc::geteuid() })
    ///     .map_gid(0, unsafe { libc::getegid() });
    /// ```
    pub fn map_root(&mut self) -> &mut Self {
        self.container.map_root();
        self
    }

    /// Maps one group ID to another.
    ///
    /// Implies `Namespace::USER`.
    ///
    /// # Implementation
    ///
    /// This modifies `/proc/{pid}/gid_map` where `{pid}` is the PID of the child
    /// process. See [`user_namespaces(7)`] for more details.
    ///
    /// [`user_namespaces(7)`]: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
    pub fn map_gid(&mut self, inside_gid: libc::gid_t, outside_gid: libc::gid_t) -> &mut Self {
        self.container.map_gid(inside_gid, outside_gid);
        self
    }

    /// Maps potentially many group IDs inside the new user namespace to group
    /// IDs outside of the user namespace.
    ///
    /// Implies `Namespace::USER`.
    ///
    /// # Implementation
    ///
    /// This modifies `/proc/{pid}/gid_map` where `{pid}` is the PID of the child
    /// process. See [`user_namespaces(7)`] for more details.
    ///
    /// [`user_namespaces(7)`]: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
    pub fn map_gid_range(
        &mut self,
        starting_inside_gid: libc::gid_t,
        starting_outside_gid: libc::gid_t,
        count: u32,
    ) -> &mut Self {
        self.container
            .map_gid_range(starting_inside_gid, starting_outside_gid, count);
        self
    }

    /// Sets the hostname of the container.
    ///
    /// Implies `Namespace::UTS`, which requires `CAP_SYS_ADMIN`.
    ///
    /// ```no_run
    /// use reverie_process::Command;
    ///
    /// let command = Command::new("cat")
    ///     .arg("/proc/sys/kernel/hostname")
    ///     .map_root()
    ///     .hostname("foobar.local");
    /// ```
    pub fn hostname<S: Into<OsString>>(&mut self, hostname: S) -> &mut Self {
        self.container.hostname(hostname);
        self
    }

    /// Sets the domain name of the container.
    ///
    /// Implies `Namespace::UTS`, which requires `CAP_SYS_ADMIN`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reverie_process::Command;
    ///
    /// let command = Command::new("cat")
    ///     .arg("/proc/sys/kernel/domainname")
    ///     .map_root()
    ///     .domainname("foobar");
    /// ```
    pub fn domainname<S: Into<OsString>>(&mut self, domainname: S) -> &mut Self {
        self.container.domainname(domainname);
        self
    }

    /// Gets the hostname of the container.
    pub fn get_hostname(&self) -> Option<&OsStr> {
        self.container.get_hostname()
    }

    /// Gets the domainname of the container.
    pub fn get_domainname(&self) -> Option<&OsStr> {
        self.container.get_domainname()
    }

    /// Adds a file system to be mounted. Note that these are mounted in the same
    /// order as given.
    ///
    /// Implies `Namespace::MOUNT`. Note that `Namespace::USER` should also have
    /// been set and `map_uid` should have been called in order to gain the
    /// privileges required to mount.
    pub fn mount(&mut self, mount: Mount) -> &mut Self {
        self.container.mount(mount);
        self
    }

    /// Adds multiple mounts.
    pub fn mounts<I>(&mut self, mounts: I) -> &mut Self
    where
        I: IntoIterator<Item = Mount>,
    {
        self.container.mounts(mounts);
        self
    }

    /// Sets up the container to have local networking only. This will prevent
    /// any network communication to the outside world.
    ///
    /// Implies `Namespace::NETWORK` and `Namespace::MOUNT`.
    ///
    /// This also causes a fresh `/sys` to be mounted to avoid seeing the host
    /// network interfaces in `/sys/class/net`.
    pub fn local_networking_only(&mut self) -> &mut Self {
        self.container.local_networking_only();
        self
    }

    /// Sets the seccomp filter. The filter is loaded immediately before `execve`
    /// and *after* all `pre_exec` callbacks have been executed. Thus, you will
    /// still be able to call filtered syscalls from `pre_exec` callbacks.
    pub fn seccomp(&mut self, filter: seccomp::Filter) -> &mut Self {
        self.container.seccomp(filter);
        self
    }

    /// Indicates that we want to listen for seccomp events using
    /// [seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html).
    ///
    /// If this is set, the seccomp listener file descriptor will be accessible
    /// via the `Child`.
    pub fn seccomp_notify(&mut self) -> &mut Self {
        self.container.seccomp_notify();
        self
    }

    /// Sets the controlling pseudoterminal for the child process).
    ///
    /// In the child process, this has the effect of:
    ///  1. Creating a new session (with `setsid()`).
    ///  2. Using an `ioctl` to set the controlling terminal.
    ///  3. Setting this file descriptor as the stdio streams.
    ///
    /// NOTE: Since this modifies the stdio streams, calling this will reset
    /// [`Self::stdin`], [`Self::stdout`], and [`Self::stderr`] back to
    /// [`Stdio::inherit()`].
    pub fn pty(&mut self, child: PtyChild) -> &mut Self {
        self.container.pty(child);
        self
    }

    /// Finds the path to the program.
    pub fn find_program(&self) -> io::Result<PathBuf> {
        let program = Path::new(self.get_program());

        if program.is_absolute() {
            // Note: We shouldn't canonicalize here since that will follow
            // symlinks. Instead, just make sure the file exists and is
            // executable.
            let metadata = program.metadata()?;

            if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
                Ok(program.to_path_buf())
            } else {
                Err(Errno::EPERM.into())
            }
        } else if program.components().count() == 1 {
            let path = self.get_env("PATH").unwrap_or_default();

            let paths = path
                .as_bytes()
                .split(|c| *c == b':')
                .map(|bytes| Path::new(OsStr::from_bytes(bytes)));

            find_program_in_paths(program, paths)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Could not find {:?} in $PATH", program),
                    )
                })?
                .canonicalize()
        } else {
            // Assume it's in the current directory
            let mut path = match self.get_current_dir() {
                Some(path) => path.to_owned(),
                None => std::env::current_dir()?,
            };
            path.push(program);
            path.canonicalize()
        }
    }
}

fn find_program_in_paths<I, S>(program: &Path, iter: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = S>,
    S: AsRef<Path>,
{
    for path in iter.into_iter() {
        let path = path.as_ref().join(program);
        if let Ok(metadata) = path.metadata() {
            if metadata.is_file() {
                if metadata.permissions().mode() & 0o111 != 0 {
                    return Some(path);
                } else {
                    continue;
                }

                #[cfg(not(unix))]
                return Some(path);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_program() {
        assert!(Command::new("cat").find_program().unwrap().is_absolute(),);
    }

    #[test]
    fn get_program() {
        assert_eq!(Command::new("cat").get_program(), "cat");
    }

    #[test]
    fn get_arg0() {
        assert_eq!(Command::new("cat").get_arg0(), "cat");
        assert_eq!(Command::new("cat").arg0("dog").get_arg0(), "dog");
        assert_eq!(
            Command::new("cat").arg0("dog").program("catdog").get_arg0(),
            "catdog"
        );
    }

    #[test]
    fn get_args() {
        assert_eq!(
            Command::new("cat")
                .arg("a")
                .arg("b")
                .arg("c")
                .get_args()
                .collect::<Vec<_>>(),
            &[OsStr::new("a"), OsStr::new("b"), OsStr::new("c")]
        );
    }

    #[test]
    fn prepend_args() {
        let mut command = Command::new("echo");
        command.args(["1", "2", "3"]);
        command.prepend_args(["a", "b", "c"]);
        assert_eq!(command.get_arg0(), "echo");

        let args = command.get_args().collect::<Vec<_>>();
        assert_eq!(
            args,
            &[
                OsStr::new("a"),
                "b".as_ref(),
                "c".as_ref(),
                "1".as_ref(),
                "2".as_ref(),
                "3".as_ref()
            ]
        );
    }
}
