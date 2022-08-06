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
use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use nix::sched::sched_setaffinity;
use nix::sched::CpuSet;
use serde::de::DeserializeOwned;
use serde::Serialize;
use syscalls::Errno;

use super::clone::clone_with_stack;
use super::env::Env;
use super::error::AddContext;
use super::error::Context;
use super::error::Error;
use super::exit_status::ExitStatus;
use super::fd::pipe;
use super::fd::write_bytes;
use super::fd::Fd;
use super::id_map::make_id_map;
use super::mount::Mount;
use super::namespace::Namespace;
use super::net::IfName;
use super::pid::Pid;
use super::pty::PtyChild;
use super::seccomp;
use super::stdio::Stdio;
use super::util::reset_signal_handling;
use super::util::to_cstring;

/// A `Container` is a configuration of how a process shall be spawned. It can,
/// but doesn't have to, include Linux namespace configuration.
///
/// NOTE: Configuring resource limits via cgroups is not yet supported.
pub struct Container {
    pub(super) env: Env,
    current_dir: Option<CString>,
    chroot: Option<CString>,
    pub(super) namespace: Namespace,
    pub(super) stdin: Stdio,
    pub(super) stdout: Stdio,
    pub(super) stderr: Stdio,
    pub(super) uid_map: Vec<(libc::uid_t, libc::uid_t, u32)>,
    pub(super) gid_map: Vec<(libc::uid_t, libc::uid_t, u32)>,
    mounts: Vec<Mount>,
    local_networking_only: bool,
    hostname: Option<OsString>,
    domainname: Option<OsString>,
    pub(super) seccomp: Option<seccomp::Filter>,
    pub(super) seccomp_notify: bool,
    pub(super) pty: Option<PtyChild>,
    /// The core number to which the new process, and descendents, will be
    /// pinned.
    affinity: Option<usize>,
}

impl Default for Container {
    fn default() -> Self {
        Self {
            env: Default::default(),
            current_dir: None,
            chroot: None,
            namespace: Default::default(),
            stdin: Stdio::inherit(),
            stdout: Stdio::inherit(),
            stderr: Stdio::inherit(),
            uid_map: Vec::new(),
            gid_map: Vec::new(),
            mounts: Vec::new(),
            local_networking_only: false,
            hostname: None,
            domainname: None,
            seccomp: None,
            seccomp_notify: false,
            pty: None,
            affinity: None,
        }
    }
}

impl Container {
    /// Creates a new `Container` that inherits everything from the parent
    /// process.
    pub fn new() -> Self {
        Self::default()
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
    /// use reverie_process::Container;
    ///
    /// let container = Container::new()
    ///         .env("PATH", "/bin");
    /// ```
    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env.set(key.as_ref(), val.as_ref());
        self
    }

    /// Adds or updates multiple environment variable mappings.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::{Container, Stdio};
    /// use std::env;
    /// use std::collections::HashMap;
    ///
    /// let filtered_env : HashMap<String, String> =
    ///     env::vars().filter(|&(ref k, _)|
    ///         k == "TERM" || k == "TZ" || k == "LANG" || k == "PATH"
    ///     ).collect();
    ///
    /// let container = Container::new()
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
        for (k, v) in vars.into_iter() {
            self.env(k, v);
        }
        self
    }

    /// Removes an environment variable mapping.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::Container;
    ///
    /// let container = Container::new()
    ///         .env_remove("PATH");
    /// ```
    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Self {
        self.env.remove(key.as_ref());
        self
    }

    /// Clears the entire environment map for the child process.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use reverie_process::Container;
    ///
    /// let container = Container::new()
    ///         .env_clear();
    /// ```
    pub fn env_clear(&mut self) -> &mut Self {
        self.env.clear();
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
    /// use reverie_process::Container;
    ///
    /// let container = Container::new()
    ///         .current_dir("/bin");
    /// ```
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.current_dir = Some(to_cstring(dir.as_ref()));
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
    /// use reverie_process::{Container, Stdio};
    ///
    /// let container = Container::new()
    ///         .stdin(Stdio::null());
    /// ```
    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdin = cfg.into();
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
    /// use reverie_process::{Container, Stdio};
    ///
    /// let container = Container::new()
    ///         .stdout(Stdio::null());
    /// ```
    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdout = cfg.into();
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
    /// use reverie_process::{Container, Stdio};
    ///
    /// let container = Container::new()
    ///         .stderr(Stdio::null());
    /// ```
    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stderr = cfg.into();
        self
    }

    /// Changes the root directory of the calling process to the specified path.
    /// This directory will be inherited by all child processes of the calling
    /// process.
    ///
    /// Note that changing the root directory may cause the program to not be
    /// found. As such, the program path should be relative to this directory.
    pub fn chroot<P: AsRef<Path>>(&mut self, chroot: P) -> &mut Self {
        self.chroot = Some(to_cstring(chroot.as_ref()));
        self
    }

    /// Unshares parts of the process execution context that are normally shared
    /// with the parent process. This is useful for executing the child process
    /// in a new namespace.
    pub fn unshare(&mut self, namespace: Namespace) -> &mut Self {
        self.namespace |= namespace;
        self
    }

    /// Returns the working directory for the child process.
    ///
    /// This returns None if the working directory will not be changed.
    pub fn get_current_dir(&self) -> Option<&Path> {
        if let Some(dir) = &self.current_dir {
            Some(Path::new(OsStr::from_bytes(dir.to_bytes())))
        } else {
            None
        }
    }

    /// Returns an iterator of the environment variables that will be set when
    /// the process is spawned. Note that this does not include any environment
    /// variables inherited from the parent process.
    pub fn get_envs(&self) -> impl Iterator<Item = (&OsStr, Option<&OsStr>)> {
        self.env.iter()
    }

    /// Returns a mapping of all environment variables that the new child process
    /// will inherit.
    pub fn get_captured_envs(&self) -> BTreeMap<OsString, OsString> {
        self.env.capture()
    }

    /// Gets an environment variable. If the child process is to inherit this
    /// environment variable from the current process, then this returns the
    /// current process's environment variable unless it is to be overridden.
    pub fn get_env<K: AsRef<OsStr>>(&self, env: K) -> Option<Cow<OsStr>> {
        self.env.get_captured(env)
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
    /// use reverie_process::Container;
    ///
    /// let container = Container::new()
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
        self.map_uid_range(inside_uid, outside_uid, 1)
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
        self.uid_map
            .push((starting_inside_uid, starting_outside_uid, count));
        self.namespace |= Namespace::USER;
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
    /// use reverie_process::Container;
    ///
    /// let container = Container::new()
    ///     .map_uid(0, unsafe { libc::geteuid() })
    ///     .map_gid(0, unsafe { libc::getegid() });
    /// ```
    pub fn map_root(&mut self) -> &mut Self {
        self.map_uid(0, unsafe { libc::geteuid() });
        self.map_gid(0, unsafe { libc::getegid() })
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
        self.map_gid_range(inside_gid, outside_gid, 1)
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
        self.namespace |= Namespace::USER;
        self.gid_map
            .push((starting_inside_gid, starting_outside_gid, count));
        self
    }

    /// Sets the hostname of the container.
    ///
    /// Implies `Namespace::UTS`, which requires `CAP_SYS_ADMIN`.
    ///
    /// ```no_run
    /// use reverie_process::Container;
    ///
    /// let container = Container::new()
    ///     .map_root()
    ///     .hostname("foobar.local");
    /// ```
    pub fn hostname<S: Into<OsString>>(&mut self, hostname: S) -> &mut Self {
        self.namespace |= Namespace::UTS;
        self.hostname = Some(hostname.into());
        self
    }

    /// Sets the domain name of the container.
    ///
    /// Implies `Namespace::UTS`, which requires `CAP_SYS_ADMIN`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use reverie_process::Container;
    ///
    /// let container = Container::new()
    ///     .map_root()
    ///     .domainname("foobar");
    /// ```
    pub fn domainname<S: Into<OsString>>(&mut self, domainname: S) -> &mut Self {
        self.namespace |= Namespace::UTS;
        self.domainname = Some(domainname.into());
        self
    }

    /// Gets the hostname of the container.
    pub fn get_hostname(&self) -> Option<&OsStr> {
        self.hostname.as_ref().map(AsRef::as_ref)
    }

    /// Gets the domainname of the container.
    pub fn get_domainname(&self) -> Option<&OsStr> {
        self.domainname.as_ref().map(AsRef::as_ref)
    }

    /// Adds a file system to be mounted. Note that these are mounted in the same
    /// order as given.
    ///
    /// Implies `Namespace::MOUNT`. Note that `Namespace::USER` should also have
    /// been set and `map_uid` should have been called in order to gain the
    /// privileges required to mount.
    pub fn mount(&mut self, mount: Mount) -> &mut Self {
        self.namespace |= Namespace::MOUNT;
        self.mounts.push(mount);
        self
    }

    /// Adds multiple mounts.
    pub fn mounts<I>(&mut self, mounts: I) -> &mut Self
    where
        I: IntoIterator<Item = Mount>,
    {
        self.namespace |= Namespace::MOUNT;
        self.mounts.extend(mounts);
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
        if !self.local_networking_only {
            self.local_networking_only = true;
            self.namespace |= Namespace::NETWORK;
            self.mount(Mount::sysfs("/sys"));
        }
        self
    }

    /// Sets the seccomp filter. The filter is loaded immediately before `execve`
    /// and *after* all `pre_exec` callbacks have been executed. Thus, you will
    /// still be able to call filtered syscalls from `pre_exec` callbacks.
    pub fn seccomp(&mut self, filter: seccomp::Filter) -> &mut Self {
        self.seccomp = Some(filter);
        self
    }

    /// Indicates that we want to listen for seccomp events using
    /// [seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html).
    ///
    /// If this is set, the seccomp listener file descriptor will be accessible
    /// via the `Child`.
    pub fn seccomp_notify(&mut self) -> &mut Self {
        self.seccomp_notify = true;
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
        self.pty = Some(child);
        self.stdin = Stdio::inherit();
        self.stdout = Stdio::inherit();
        self.stderr = Stdio::inherit();
        self
    }

    /// Sets the CPU to which the child threads/processes will be pinned.
    pub fn affinity(&mut self, affinity: usize) -> &mut Self {
        self.affinity = Some(affinity);
        self
    }

    /// Called by the child process after `clone` to get itself set up for either
    /// `execve` or running an arbitrary function.
    ///
    /// NOTE: Although this function takes `&mut self`, it is only called in the
    /// context of the child process (which has a copy-on-write view of the
    /// parent's virtual memory). Thus, the parent's version isn't actually
    /// modified.
    pub(super) fn setup(
        &mut self,
        context: &ChildContext,
        pre_exec: &mut [Box<dyn FnMut() -> Result<(), Errno> + Send + Sync>],
    ) -> Result<(), Error> {
        // NOTE: This function MUST NOT allocate or deallocate any memory! Doing
        // so can cause random, difficult to diagnose deadlocks.

        if let Some(pty) = self.pty.take() {
            // NOTE: This is done *before* setting the stdio streams so that the
            // user can still override individual streams if they only want them
            // to be partially attached to the tty.
            pty.login().context(Context::Tty)?;
        }

        if let Some(fd) = context.stdin {
            fd.dup2(libc::STDIN_FILENO)
                .context(Context::Stdio)?
                .leave_open();
        }
        if let Some(fd) = context.stdout {
            fd.dup2(libc::STDOUT_FILENO)
                .context(Context::Stdio)?
                .leave_open();
        }
        if let Some(fd) = context.stderr {
            fd.dup2(libc::STDERR_FILENO)
                .context(Context::Stdio)?
                .leave_open();
        }

        unsafe { reset_signal_handling() }.context(Context::ResetSignals)?;

        // Set up UID and GID maps.
        if !context.uid_map.is_empty() {
            context.map_uid().context(Context::MapUid)?;
        }

        if !context.gid_map.is_empty() {
            context.setgroups(false).context(Context::MapGid)?;
            context.map_gid().context(Context::MapGid)?;
        }

        // Set host name, if any.
        if let Some(name) = &self.hostname {
            Error::result(
                unsafe { libc::sethostname(name.as_bytes().as_ptr() as *const _, name.len()) },
                Context::Hostname,
            )?;
        }

        // Set domain name, if any.
        if let Some(name) = &self.domainname {
            Error::result(
                unsafe { libc::setdomainname(name.as_bytes().as_ptr() as *const _, name.len()) },
                Context::Domainname,
            )?;
        }

        // Mount all the things.
        for mount in &mut self.mounts {
            mount.mount().context(Context::Mount)?;
        }

        // Change root directory. Note that we do this *after* mounting anything
        // so that bind mounts sources that live outside of the chroot directory
        // can work.
        if let Some(chroot) = &self.chroot {
            Error::result(unsafe { libc::chroot(chroot.as_ptr()) }, Context::Chroot)?;
        }

        // Set working directory, if any.
        if let Some(current_dir) = &self.current_dir {
            Error::result(unsafe { libc::chdir(current_dir.as_ptr()) }, Context::Chdir)?;
        }

        // Configure networking.
        // TODO: Generalize this a bit to allow more complex configuration.
        if self.local_networking_only {
            // Need a socket to access the network interface.
            let sock = Fd::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP)
                .context(Context::Network)?;

            let loopback = IfName::LOOPBACK;

            // Bring up the loopback interface in the newly mounted sysfs.
            let flags = loopback.get_flags(&sock).context(Context::Network)?;
            let flags = flags | libc::IFF_UP as i16;
            loopback.set_flags(&sock, flags).context(Context::Network)?;
        }

        if let Some(cpu) = self.affinity {
            let mut cpu_set = CpuSet::new();
            cpu_set.set(cpu).context(Context::Affinity)?;
            sched_setaffinity(nix::unistd::Pid::from_raw(0), &cpu_set)
                .context(Context::Affinity)?;
        }

        // NOTE: We must call our pre_exec callbacks BEFORE installing the
        // seccomp filter because our callbacks could be calling syscalls that
        // our seccomp filter may be intending to block.
        for f in pre_exec {
            f().context(Context::PreExec)?;
        }

        // Set up the seccomp filter, if any.
        if let Some(filter) = &self.seccomp {
            use core::sync::atomic::Ordering;

            // no_new_privs must be set or seccomp will not work.
            Error::result(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                Context::Seccomp,
            )?;

            // NOTE: If the supervisor (parent process) wants to listen for
            // seccomp notifications, we need to be able to pass the file
            // descriptor to the parent. The most common way to do this is to
            // set up a socket connection and send the file descriptor. However,
            // since we just set up a seccomp filter, the filter could apply to
            // any syscalls we make from here on out. This is especially
            // troublesome if we're also ptracing this child because our syscall
            // could result in a premature seccomp stop and cause a deadlock.
            // Thus, instead, we should pass the file descriptor to the parent
            // process without making any syscalls. The only way to do that is
            // to create some shared memory and atomically set an integer.
            if let Some(shared_fd) = context.seccomp_fd {
                use std::os::unix::io::IntoRawFd;

                let fd = filter
                    .load_and_listen()
                    .context(Context::Seccomp)?
                    .into_raw_fd();

                shared_fd.store(fd, Ordering::Relaxed);

                // Wait until the parent changes the value back. The parent only
                // does this after it calls pidfd_getfd to copy the file
                // descriptor into its own file descriptor table. After this,
                // the file descriptor can be safely closed, but we won't do
                // that in order to avoid doing a syscall. The fd will be closed
                // automatically when execve happens anyway.
                //
                // NOTE: Again, we must not perform any syscalls after the
                // seccomp filter has been installed (except for execve of
                // course).
                while shared_fd.load(Ordering::Relaxed) == fd {
                    // Spin spin spin
                }
            } else {
                filter.load().context(Context::Seccomp)?;
            }
        }

        Ok(())
    }

    /// Runs a function in a new process with the specified namespaces unshared. This
    /// blocks until the function itself returns and the process has exited.
    ///
    /// # Safety
    ///
    ///  - This should be called early on in the life of a process, before any
    ///    other threads are created. This reduces the chance that any global
    ///    resources (like the Tokio runtime) have been created yet.
    ///
    ///  - Memory allocated in the parent must not be freed in the child,
    ///    especially if using jemalloc where a separate thread does deallocations.
    pub fn run<F, T>(&mut self, mut f: F) -> Result<T, RunError>
    where
        F: FnMut() -> T,
        T: Serialize + DeserializeOwned,
    {
        let clone_flags = self.namespace.bits() | libc::SIGCHLD;

        let uid_map = &make_id_map(&self.uid_map);
        let gid_map = &make_id_map(&self.gid_map);

        let context = ChildContext {
            // TODO: Honor stdio options. For now, always inherit from the
            // parent process.
            stdin: None,
            stdout: None,
            stderr: None,
            uid_map,
            gid_map,
            seccomp_fd: None,
        };

        // Use a pipe for getting the result of the function out of the child
        // process.
        let (mut reader, writer) = pipe()?;

        let writer_fd = writer.as_raw_fd();

        // NOTE: Must use a dynamically allocated stack here. Programs expect to
        // have at least 2 MB of stack space and if we've already used up some
        // stack space before this is called we could overflow the stack.
        let mut stack = vec![0u8; 1024 * 1024 * 2];

        // Disable io redirection just before forking. We want the child process to
        // be able to call `println!()` and have that output go to stdout.
        //
        // See: https://github.com/rust-lang/rust/issues/35136
        let output_capture = std::io::set_output_capture(None);

        let result = clone_with_stack(
            || {
                let value = self.setup(&context, &mut []).map(|()| f());

                let writer = std::io::BufWriter::new(Fd::new(writer_fd));

                // Serialize this result with bincode and send it to the parent
                // process via a pipe.
                //
                // TODO: Handle serialization errors(?)
                bincode::serialize_into(writer, &value).expect("Failed to serialize return value");

                0
            },
            clone_flags,
            &mut stack,
        );

        std::io::set_output_capture(output_capture);

        let child = WaitGuard::new(result?);

        // The writer end must be dropped first so that our reader doesn't block
        // forever.
        drop(writer);

        // Read the return value. Note that we do this *before* waiting on the
        // process to exit. Otherwise, for return values that exceed the pipe
        // capacity, we would deadlock.
        let mut buf = Vec::new();
        match reader.read_to_end(&mut buf) {
            Ok(0) => {
                // The writer end was closed before anything could be written.
                // This indicates that the process exited before the return
                // value could be serialized. The only thing we can do in this
                // case is collect the exit status of the process.
                //
                // NOTE: Since we always send `Result<T, _>` through the pipe,
                // we can guarantee that a successful serialization will never
                // be 0 bytes (since it always takes more than 0 bytes to encode
                // that type).
                //
                // NOTE: Since `WaitGuard` is used, we guarantee that the
                // process will be waited on in the other cases.
                Err(RunError::ExitStatus(child.wait()?))
            }
            Ok(n) => {
                // FIXME: Handle errors
                let value: Result<T, Error> = bincode::deserialize(&buf[0..n]).unwrap();
                Ok(value.unwrap())
            }
            Err(err) => {
                // FIXME: Handle this error
                panic!("Got unexpected error: {}", err)
            }
        }
    }
}

pub(super) struct ChildContext<'a> {
    pub stdin: Option<&'a Fd>,
    pub stdout: Option<&'a Fd>,
    pub stderr: Option<&'a Fd>,
    pub uid_map: &'a [u8],
    pub gid_map: &'a [u8],
    pub seccomp_fd: Option<&'a core::sync::atomic::AtomicI32>,
}

impl<'a> ChildContext<'a> {
    fn map_uid(&self) -> Result<(), Errno> {
        write_bytes(b"/proc/self/uid_map\0", self.uid_map)
    }

    fn map_gid(&self) -> Result<(), Errno> {
        write_bytes(b"/proc/self/gid_map\0", self.gid_map)
    }

    fn setgroups(&self, allow: bool) -> Result<(), Errno> {
        write_bytes(
            b"/proc/self/setgroups\0",
            if allow { b"allow\0" } else { b"deny\0" },
        )
    }
}

/// An error that ocurred while running a containerized function.
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum RunError {
    /// An error that occurred while spawning the container.
    #[error("Process failed to spawn: {0}")]
    Spawn(#[from] Error),

    /// The function exited prematurely. This can happen if the function called
    /// `std::process::exit(0)`, preventing the return value from being sent to
    /// the parent. It can also happen if the process panics.
    #[error("Process exited with code: {0:?}")]
    ExitStatus(ExitStatus),
}

impl From<Errno> for RunError {
    fn from(errno: Errno) -> Self {
        Self::Spawn(Error::from(errno))
    }
}

// Helper guard for making sure that the process gets waited on even if an error
// is encountered.
struct WaitGuard(Option<Pid>);

impl WaitGuard {
    pub fn new(pid: Pid) -> Self {
        Self(Some(pid))
    }

    /// Eagerly waits for the pid. Otherwise, it'll get waited on upon drop.
    pub fn wait(mut self) -> Result<ExitStatus, Errno> {
        let pid = self.0.take().unwrap();

        let mut status = 0;
        let ret = Errno::result(unsafe { libc::waitpid(pid.as_raw(), &mut status, 0) })?;
        assert_ne!(ret, 0);

        Ok(ExitStatus::from_raw(status))
    }
}

impl Drop for WaitGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            let mut status = 0;
            unsafe {
                libc::waitpid(pid.as_raw(), &mut status, 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::signal::Signal;

    use super::*;

    #[test]
    fn can_panic() {
        assert_eq!(
            Container::new().run(|| panic!()),
            Err(RunError::ExitStatus(ExitStatus::Signaled(
                Signal::SIGABRT,
                true
            )))
        );
    }

    #[test]
    fn is_new_process() {
        let my_pid = unsafe { libc::getpid() };

        assert_eq!(
            Container::new().run(|| {
                assert_ne!(unsafe { libc::getpid() }, 1);
                assert_ne!(unsafe { libc::getpid() }, my_pid);
                assert_eq!(unsafe { libc::getppid() }, my_pid);
            }),
            Ok(())
        );
    }

    #[test]
    fn pid_namespace() {
        assert_eq!(
            Container::new()
                .unshare(Namespace::USER | Namespace::PID)
                .run(|| {
                    // New PID namespace, so this should be the init process.
                    assert_eq!(unsafe { libc::getpid() }, 1);
                }),
            Ok(())
        );
    }

    #[test]
    fn return_value() {
        assert_eq!(Container::new().run(|| 42), Ok(42));

        assert_eq!(
            Container::new().run(|| String::from("foobar")),
            Ok("foobar".into())
        );
    }

    #[test]
    fn huge_return_value() {
        assert_eq!(
            Container::new().run(|| {
                // Need something larger than /proc/sys/fs/pipe-max-size, which
                // is typically 1MB.
                vec![42; 10 * 1024 * 1024 /* 10 MB */]
            }),
            Ok(vec![42; 10 * 1024 * 1024])
        );
    }

    #[test]
    pub fn bind_to_low_port() {
        use std::net::Ipv4Addr;
        use std::net::SocketAddrV4;
        use std::net::TcpListener;

        let addr = Container::new()
            .map_root()
            .local_networking_only()
            .run(|| {
                let listener = TcpListener::bind("127.0.0.1:80").unwrap();
                listener.local_addr().unwrap()
            })
            .unwrap();

        assert_eq!(
            addr,
            SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80).into()
        );
    }

    #[test]
    pub fn pin_affinity_to_all_cores() -> Result<(), Error> {
        use std::collections::HashMap;

        use raw_cpuid::CpuId;

        let cpus = num_cpus::get();
        println!("Total cpus {}", cpus);

        // Map the apic_id to the number of times we observed it:
        let mut results: HashMap<u8, usize> = HashMap::new();
        for core in 0..cpus {
            println!("  Launching guest with affinity set to {}", core);
            let mut container = Container::new();
            container.affinity(core);
            let which_core = container
                .run(|| {
                    let cpuid = CpuId::new();
                    cpuid
                        .get_feature_info()
                        .expect("cpuid failed")
                        .initial_local_apic_id()
                })
                .unwrap();
            println!("    Guest sees its on APIC id {}", which_core);
            *results.entry(which_core).or_default() += 1;
        }

        println!("Final table size {:?}", results.len());
        assert_eq!(results.values().fold(0, |n, v| std::cmp::max(n, *v)), 1);
        Ok(())
    }
}
