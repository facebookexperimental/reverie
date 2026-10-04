/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
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
use std::io::Write;
#[cfg(test)]
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
#[cfg(test)]
use std::sync::atomic::Ordering;

use nix::sched::CpuSet;
use nix::sched::sched_setaffinity;
use serde::Serialize;
use serde::de::DeserializeOwned;
use syscalls::Errno;

use super::clone::child_stack;
use super::clone::clone_with_stack;
use super::env::Env;
use super::error::AddContext;
use super::error::Context;
use super::error::Error;
use super::exit_status::ExitStatus;
use super::fd::Fd;
use super::fd::pipe;
use super::fd::write_bytes;
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
    /// Returns the configured features that cannot be represented by
    /// `std::process::Command`.
    pub(super) fn std_conversion_blockers(&self) -> Vec<&'static str> {
        // Keep this exhaustive: adding Container state must fail to compile
        // until the standard-command conversion explicitly classifies it.
        let Self {
            env: _,
            current_dir: _,
            chroot,
            namespace,
            stdin: _,
            stdout: _,
            stderr: _,
            uid_map,
            gid_map,
            mounts,
            local_networking_only,
            hostname,
            domainname,
            seccomp,
            seccomp_notify,
            pty,
            affinity,
        } = self;

        let mut blockers = Vec::new();

        if chroot.is_some() {
            blockers.push("chroot");
        }
        if !namespace.is_empty() {
            blockers.push("Linux namespaces");
        }
        if !uid_map.is_empty() {
            blockers.push("user ID mappings");
        }
        if !gid_map.is_empty() {
            blockers.push("group ID mappings");
        }
        if !mounts.is_empty() {
            blockers.push("mounts");
        }
        if *local_networking_only {
            blockers.push("local-only networking");
        }
        if hostname.is_some() {
            blockers.push("hostname");
        }
        if domainname.is_some() {
            blockers.push("domain name");
        }
        if seccomp.is_some() {
            blockers.push("seccomp filter");
        }
        if *seccomp_notify {
            blockers.push("seccomp notification");
        }
        if pty.is_some() {
            blockers.push("pseudoterminal");
        }
        if affinity.is_some() {
            blockers.push("CPU affinity");
        }

        blockers
    }

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
    /// let container = Container::new().env("PATH", "/bin");
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
    /// use std::collections::HashMap;
    /// use std::env;
    ///
    /// use reverie_process::Container;
    /// use reverie_process::Stdio;
    ///
    /// let filtered_env: HashMap<String, String> = env::vars()
    ///     .filter(|&(ref k, _)| k == "TERM" || k == "TZ" || k == "LANG" || k == "PATH")
    ///     .collect();
    ///
    /// let container = Container::new()
    ///     .stdin(Stdio::null())
    ///     .stdout(Stdio::inherit())
    ///     .env_clear()
    ///     .envs(&filtered_env);
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
    /// let container = Container::new().env_remove("PATH");
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
    /// let container = Container::new().env_clear();
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
    /// let container = Container::new().current_dir("/bin");
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
    /// use reverie_process::Container;
    /// use reverie_process::Stdio;
    ///
    /// let container = Container::new().stdin(Stdio::null());
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
    /// use reverie_process::Container;
    /// use reverie_process::Stdio;
    ///
    /// let container = Container::new().stdout(Stdio::null());
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
    /// use reverie_process::Container;
    /// use reverie_process::Stdio;
    ///
    /// let container = Container::new().stderr(Stdio::null());
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
    pub fn get_env<K: AsRef<OsStr>>(&self, env: K) -> Option<Cow<'_, OsStr>> {
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
    /// let container = Container::new().map_uid(1, unsafe { libc::getuid() });
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
    /// let container = Container::new().map_root().hostname("foobar.local");
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
    /// let container = Container::new().map_root().domainname("foobar");
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
        self.setup_before_filter(context, pre_exec)?;
        self.setup_filter(context)
    }

    fn setup_before_filter(
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

        Ok(())
    }

    fn setup_filter(&self, context: &ChildContext) -> Result<(), Error> {
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
        // stack space before this is called we could overflow the stack. See
        // CHILD_STACK_SIZE for the size child_stack() provides (8 MiB).
        let mut stack = child_stack()?;

        // Disable io redirection just before forking. We want the child process to
        // be able to call `println!()` and have that output go to stdout.
        //
        // See: https://github.com/rust-lang/rust/issues/35136
        //
        // Another way around this weirdness is to not use the default
        // `print!()` and `println!()` macros so that we can completely bypass
        // this output capturing.
        #[cfg(feature = "nightly")]
        let output_capture = std::io::set_output_capture(None);

        let result = clone_with_stack(
            || {
                let value = self.setup(&context, &mut []).map(|()| f());

                let mut writer = std::io::BufWriter::new(Fd::new(writer_fd));

                // Serialize this result with bincode and send it to the parent
                // process via a pipe.
                //
                // TODO: Handle serialization errors(?)
                bincode::serde::encode_into_std_write(
                    &value,
                    &mut writer,
                    bincode::config::legacy(),
                )
                .expect("Failed to serialize return value");

                0
            },
            clone_flags,
            &mut stack,
        );

        #[cfg(feature = "nightly")]
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
                let value: Result<T, Error> =
                    bincode::serde::decode_from_slice(&buf[0..n], bincode::config::legacy())
                        .unwrap()
                        .0;
                value.map_err(RunError::Spawn)
            }
            Err(err) => {
                // FIXME: Handle this error
                panic!("Got unexpected error: {}", err)
            }
        }
    }

    /// Runs child setup and a parent readiness callback before installing the
    /// unchanged seccomp filter and entering the child workload.
    ///
    /// `child_start` runs after namespace/filesystem setup, without creating a
    /// helper task. It returns child-local state and may transfer up to
    /// [`MAX_STARTUP_FDS`] owned descriptors through its context. `parent_start`
    /// runs in the original process, with the actual owned child and received
    /// descriptors, and must return only when its external resources are ready.
    /// Its returned owner stays in the parent. Only then may `run` consume the
    /// child state. Startup endpoint aliases close before seccomp is installed.
    ///
    /// The positive, representable `timeout` gives the entire protocol one
    /// monotonic I/O deadline, including time spent in callbacks. It does not
    /// preempt arbitrary callback code or destructors. Failure cancels and
    /// reaps the owned child; actual cleanup errors remain errors. Kernel waits
    /// for an uninterruptible child still require outer process supervision.
    ///
    /// Like [`Self::run`], call this before starting other threads. No signal
    /// handler or other thread may reap this child; SIGCHLD auto-reaping is
    /// rejected before clone. Callbacks must obey the existing fork-safety
    /// rules, close unrelated inherited descriptors, and not fork workers in
    /// the child. This API does not prove capture completion or guest teardown.
    ///
    /// Results are drained before wait, including large values. `run` returns
    /// a deferred cleanup value just as [`Self::run_with_deferred_drop`] does;
    /// the returned handle's [`DeferredContainerRun::finalize_with_status`]
    /// checks the real terminal status before yielding the value.
    pub fn run_with_startup<P, C, F, O, S, T, D>(
        &mut self,
        timeout: std::time::Duration,
        parent_start: P,
        mut child_start: C,
        mut run: F,
    ) -> Result<(O, DeferredContainerRun<T>), StartupRunError>
    where
        P: FnOnce(ParentStartContext<'_>) -> Result<O, StartupError>,
        C: FnMut(&mut ChildStartContext) -> Result<S, StartupError>,
        F: FnMut(S) -> (T, D),
        T: Serialize + DeserializeOwned,
    {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or(StartupRunError::BeforeClone(StartupError::InvalidTimeout))?;
        let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
        Errno::result(unsafe {
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition)
        })
        .map_err(|error| StartupRunError::BeforeClone(error.into()))?;
        if disposition.sa_sigaction == libc::SIG_IGN
            || disposition.sa_flags & libc::SA_NOCLDWAIT != 0
        {
            return Err(StartupRunError::BeforeClone(StartupError::Io(
                Errno::ECHILD,
            )));
        }
        let (parent_socket, child_socket) =
            StartupSocket::pair(deadline).map_err(StartupRunError::BeforeClone)?;
        let uid_map = &make_id_map(&self.uid_map);
        let gid_map = &make_id_map(&self.gid_map);
        let context = ChildContext {
            stdin: None,
            stdout: None,
            stderr: None,
            uid_map,
            gid_map,
            seccomp_fd: None,
        };
        let (mut reader, writer) =
            pipe().map_err(|error| StartupRunError::BeforeClone(error.into()))?;
        let writer_fd = writer.as_raw_fd();
        let reader_fd = reader.as_raw_fd();
        let parent_fd = parent_socket.fd.as_raw_fd();
        let child_fd = child_socket.fd.as_raw_fd();
        let mut stack =
            child_stack().map_err(|error| StartupRunError::BeforeClone(error.into()))?;
        let clone_flags = self.namespace.bits() | libc::SIGCHLD;
        #[cfg(feature = "nightly")]
        let output_capture = std::io::set_output_capture(None);
        let result = clone_with_stack(
            || {
                self.startup_child_run(
                    &context,
                    StartupChildIo {
                        parent_fd,
                        child_fd,
                        reader_fd,
                        writer_fd,
                        deadline,
                    },
                    &mut child_start,
                    &mut run,
                )
            },
            clone_flags,
            &mut stack,
        );
        #[cfg(feature = "nightly")]
        std::io::set_output_capture(output_capture);
        let pid = result.map_err(|error| StartupRunError::BeforeClone(error.into()))?;
        let mut child = StartupChild {
            wait: Some(WaitGuard::new(pid)),
            pidfd: None,
        };
        drop(child_socket);
        drop(writer);
        child.pidfd = match Fd::pidfd_open(pid.as_raw(), 0) {
            Ok(fd) => Some(fd),
            Err(error) => return Err(child.fail(error.into())),
        };
        let descriptors =
            match parent_socket
                .receive(Some(STARTUP_REQUEST))
                .and_then(|descriptors| {
                    // Authorize nothing until the one request, including all ancillary
                    // rights and its true stream EOF, has been validated.
                    parent_socket.receive(None)?;
                    Ok(descriptors)
                }) {
                Ok(descriptors) => descriptors,
                Err(error) => return Err(child.fail(error)),
            };
        let owner = match parent_start(ParentStartContext {
            child_pid: child.wait.as_ref().unwrap().0.unwrap(),
            // SAFETY: the context borrows this still-owned descriptor for the call.
            child_pidfd: unsafe {
                std::os::fd::BorrowedFd::borrow_raw(child.pidfd.as_ref().unwrap().as_raw_fd())
            },
            deadline,
            descriptors,
        }) {
            Ok(owner) => owner,
            Err(error) => return Err(child.fail(error)),
        };
        let ready = (|| {
            parent_socket.send(STARTUP_READY, &StartupFds::default(), None)?;
            parent_socket.close_write()?;
            // No fallible startup validation remains after final permission.
            #[cfg(test)]
            if STARTUP_TEST_FAULT.with(|fault| fault.get())
                == StartupTestFault::ObservePermissionLate
            {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Ok::<_, StartupError>(())
        })();
        if let Err(error) = ready {
            // Reap before dropping the parent's resource owner.
            return Err(child.fail(error));
        }
        drop(parent_socket);
        let mut bytes = Vec::new();
        match reader.read_to_end(&mut bytes) {
            Ok(0) => return Err(child.fail(StartupError::MissingResult)),
            Ok(_) => (),
            Err(error) => {
                return Err(child.fail(StartupError::Io(Errno::new(
                    error.raw_os_error().unwrap_or(libc::EIO),
                ))));
            }
        }
        let value = match bincode::serde::decode_from_slice::<Result<T, StartupError>, _>(
            &bytes,
            bincode::config::legacy(),
        ) {
            Ok((Ok(value), used)) if used == bytes.len() => value,
            Ok((Err(error), used)) if used == bytes.len() => return Err(child.fail(error)),
            _ => return Err(child.fail(StartupError::Protocol)),
        };
        Ok((
            owner,
            DeferredContainerRun {
                value: Some(value),
                child: child.into_wait(),
            },
        ))
    }

    // Shared verbatim child exchange/setup/result path for both ownership APIs.
    fn startup_child_run<C, F, S, T, U>(
        &mut self,
        context: &ChildContext<'_>,
        io: StartupChildIo,
        child_start: &mut C,
        run: &mut F,
    ) -> i32
    where
        C: FnMut(&mut ChildStartContext) -> Result<S, StartupError>,
        F: FnMut(S) -> (T, U),
        T: Serialize,
    {
        let StartupChildIo {
            parent_fd,
            child_fd,
            reader_fd,
            writer_fd,
            deadline,
        } = io;
        // The outer Rust owners live only in the parent. This branch
        // owns its inherited child endpoint and result writer only.
        unsafe {
            libc::close(parent_fd);
            libc::close(reader_fd);
        }
        let socket = StartupSocket {
            fd: Fd::new(child_fd),
            deadline,
        };
        let startup = (|| {
            self.setup_before_filter(context, &mut [])
                .map_err(StartupError::Setup)?;
            let mut child_context = ChildStartContext {
                deadline,
                descriptors: StartupFds::default(),
                failure: None,
            };
            let state = child_start(&mut child_context)?;
            if let Some(error) = child_context.failure {
                return Err(error);
            }
            socket.send(STARTUP_REQUEST, &child_context.descriptors, None)?;
            drop(child_context);
            socket.close_write()?;
            socket.receive(Some(STARTUP_READY))?;
            socket.receive(None)?; // Require completed final permission.

            Ok(state)
        })();
        let state = match startup {
            Ok(state) => state,
            Err(error) => {
                let _ = socket.send(STARTUP_FAILURE, &StartupFds::default(), Some(error));
                drop(socket);
                let mut writer = std::io::BufWriter::new(Fd::new(writer_fd));
                bincode::serde::encode_into_std_write(
                    Err::<T, StartupError>(error),
                    &mut writer,
                    bincode::config::legacy(),
                )
                .expect("Failed to serialize startup refusal");
                writer.flush().expect("Failed to flush startup refusal");
                drop(writer);
                return 1;
            }
        };
        drop(socket);
        let (value, deferred) = match self.setup_filter(context) {
            Ok(()) => {
                let (value, deferred) = run(state);
                (Ok(value), Some(deferred))
            }
            Err(error) => (Err(StartupError::Setup(error)), None),
        };
        let mut writer = std::io::BufWriter::new(Fd::new(writer_fd));
        bincode::serde::encode_into_std_write(&value, &mut writer, bincode::config::legacy())
            .expect("Failed to serialize return value");
        writer.flush().expect("Failed to flush return value");
        drop(writer);
        drop(deferred);
        0
    }

    /// Runs the existing startup protocol with retained child/result ownership.
    ///
    /// Call before starting threads; no handler or other thread may reap this
    /// child. The callbacks are borrowed. Parent setup returns unit: retain
    /// initialized parent resources outside this call and pair them with every
    /// returned owner, including errors. This API cannot clean external state.
    /// Child callbacks obey the same fork-safety and no-child-worker contract
    /// as [`Self::run_with_startup`]. Namespace/filter/signal policy is unchanged.
    ///
    /// Linux pidfd support is required and probed before clone. Startup uses
    /// one finite timeout, without preempting callbacks. Result acquisition then
    /// blocks draining the pipe before wait, with no workload deadline or value
    /// size cap. On read failure the same FD and partial bytes remain owned.
    /// Generic deserialization happens only after actual successful child wait.
    /// Explicit cleanup observation is bounded; implicit Drop can block and
    /// requires outer process supervision for uninterruptible/unknown cleanup.
    pub fn run_with_startup_owned<P, C, F, S, T, U>(
        &mut self,
        timeout: std::time::Duration,
        parent_start: &mut P,
        child_start: &mut C,
        run: &mut F,
    ) -> Result<OwnedDeferredContainerRun<T>, StartupOwnedFailure<T>>
    where
        P: FnMut(ParentStartContext<'_>) -> Result<(), StartupError>,
        C: FnMut(&mut ChildStartContext) -> Result<S, StartupError>,
        F: FnMut(S) -> (T, U),
        T: Serialize,
    {
        use std::os::fd::AsFd;
        let before = |cause| StartupOwnedFailure::BeforeClone { cause };
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or_else(|| before(StartupError::InvalidTimeout))?;
        let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
        Errno::result(unsafe {
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition)
        })
        .map_err(|error| before(error.into()))?;
        if disposition.sa_sigaction == libc::SIG_IGN
            || disposition.sa_flags & libc::SA_NOCLDWAIT != 0
        {
            return Err(before(StartupError::Io(Errno::ECHILD)));
        }
        let (parent_socket, child_socket) = StartupSocket::pair(deadline).map_err(before)?;
        let uid_map = &make_id_map(&self.uid_map);
        let gid_map = &make_id_map(&self.gid_map);
        let context = ChildContext {
            stdin: None,
            stdout: None,
            stderr: None,
            uid_map,
            gid_map,
            seccomp_fd: None,
        };
        let (reader, writer) = pipe().map_err(|error| before(error.into()))?;
        #[cfg(test)]
        OWNED_RESULT_PIPE_CAPACITY.with(|capacity| {
            capacity.set(
                Errno::result(unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETPIPE_SZ) }).ok(),
            );
        });
        let io = StartupChildIo {
            parent_fd: parent_socket.fd.as_raw_fd(),
            child_fd: child_socket.fd.as_raw_fd(),
            reader_fd: reader.as_raw_fd(),
            writer_fd: writer.as_raw_fd(),
            deadline,
        };
        let mut stack = child_stack().map_err(|error| before(error.into()))?;
        #[cfg(feature = "nightly")]
        let output_capture = std::io::set_output_capture(None);
        let namespace = self.namespace;
        let result = super::clone::clone_with_stack_owned(
            || self.startup_child_run(&context, io, child_start, run),
            namespace,
            &mut stack,
        );
        #[cfg(feature = "nightly")]
        std::io::set_output_capture(output_capture);
        let child = OwnedContainerCleanup::new(result.map_err(|error| before(error.into()))?);
        // Install the guard before any fallible parent step or user callback.
        let mut owned = OwnedFinalization::new(child, reader);
        drop(child_socket);
        drop(writer);
        if owned.cleanup().pidfd.is_none() {
            return Err(owned.fail(OwnedRunFailure::Startup(StartupError::Protocol), deadline));
        }
        let ready = (|| {
            let descriptors = parent_socket.receive(Some(STARTUP_REQUEST))?;
            parent_socket.receive(None)?;
            parent_start(ParentStartContext {
                child_pid: owned.cleanup().pid,
                child_pidfd: owned.cleanup().pidfd.as_ref().unwrap().as_fd(),
                deadline,
                descriptors,
            })?;
            parent_socket.send(STARTUP_READY, &StartupFds::default(), None)?;
            parent_socket.close_write()?;
            // As in the original path, no fallible startup check follows final
            // permission. Work may already have started when O is rescheduled.
            Ok::<_, StartupError>(())
        })();
        if let Err(error) = ready {
            return Err(owned.fail(OwnedRunFailure::Startup(error), deadline));
        }
        drop(parent_socket);
        if let Err(error) = owned.drain() {
            return Err(owned.fail(error, deadline));
        }
        Ok(OwnedDeferredContainerRun { inner: owned })
    }

    /// Runs a deferred workload while retaining the original child/result owner.
    ///
    /// This has the fork-safety requirements of [`Self::run`]: call before
    /// starting threads, with no handler or other thread reaping this child.
    /// The workload may create its own workers; it is not subject to the
    /// startup callbacks' no-child-worker contract. The borrowed factory and
    /// any external parent resources must remain alive through every returned
    /// owner, including errors. Ownership here covers the direct child, not
    /// arbitrary descendants.
    /// A normal raw-clone callback return exits only its calling thread. Join
    /// worker threads before returning, or arrange an explicit group exit
    /// (for example `_exit` in `D`) if those workers must end with the callback.
    ///
    /// The child publishes and closes its encoded result before dropping `D`.
    /// Linux pidfd support is required and probed before clone. After clone,
    /// failures retain the original wait, reader and exact partial bytes, with
    /// **no implicit cleanup attempt**. The workload may already have started
    /// before such a failure is detected. Call the retained owner's explicit
    /// cancellation/observation methods with an absolute deadline; failed
    /// results stay failed even when the child later exits successfully.
    /// Atomic pidfd availability is validated after the initial drain: a real
    /// read failure is reported first; otherwise missing identity is a protocol
    /// refusal with complete encoded bytes and EOF retained.
    ///
    /// Initial result acquisition blocks draining the pipe before wait, without
    /// a workload deadline or size cap. Explicit finalization bounds do not
    /// bound that acquisition or child serialization. Implicit owner Drop can
    /// block; callers requiring a hard bound need outer process supervision.
    /// Generic result decoding is available only after an actual successful
    /// child wait, including for an encoded container-setup refusal.
    pub fn run_with_deferred_drop_owned<F, T, D>(
        &mut self,
        run: &mut F,
    ) -> Result<OwnedDeferredContainerRun<T>, StartupOwnedFailure<T>>
    where
        F: FnMut() -> (T, D),
        T: Serialize,
    {
        let before = |cause| StartupOwnedFailure::BeforeClone { cause };
        let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
        Errno::result(unsafe {
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition)
        })
        .map_err(|error| before(error.into()))?;
        if disposition.sa_sigaction == libc::SIG_IGN
            || disposition.sa_flags & libc::SA_NOCLDWAIT != 0
        {
            return Err(before(StartupError::Io(Errno::ECHILD)));
        }
        let uid_map = &make_id_map(&self.uid_map);
        let gid_map = &make_id_map(&self.gid_map);
        let context = ChildContext {
            stdin: None,
            stdout: None,
            stderr: None,
            uid_map,
            gid_map,
            seccomp_fd: None,
        };
        let (reader, writer) = pipe().map_err(|error| before(error.into()))?;
        let reader_fd = reader.as_raw_fd();
        let writer_fd = writer.as_raw_fd();
        let mut stack = child_stack().map_err(|error| before(error.into()))?;
        #[cfg(feature = "nightly")]
        let output_capture = std::io::set_output_capture(None);
        let namespace = self.namespace;
        let result = super::clone::clone_with_stack_owned(
            || {
                // Only the child writer is transferred into an owning wrapper.
                // Close the inherited reader before setup or workload effects.
                unsafe { libc::close(reader_fd) };
                let (value, deferred) = match self.setup(&context, &mut []) {
                    Ok(()) => {
                        let (value, deferred) = run();
                        (Ok(value), Some(deferred))
                    }
                    Err(error) => (Err(StartupError::Setup(error)), None),
                };
                let mut writer = std::io::BufWriter::new(Fd::new(writer_fd));
                bincode::serde::encode_into_std_write(
                    &value,
                    &mut writer,
                    bincode::config::legacy(),
                )
                .expect("Failed to serialize return value");
                writer.flush().expect("Failed to flush return value");
                drop(writer);
                drop(deferred);
                0
            },
            namespace,
            &mut stack,
        );
        #[cfg(feature = "nightly")]
        std::io::set_output_capture(output_capture);
        let child = OwnedContainerCleanup::new(result.map_err(|error| before(error.into()))?);
        // Nothing fallible or user-controlled precedes installation of this
        // original wait owner after clone has succeeded.
        let mut owned = OwnedFinalization::new(child, reader);
        drop(writer);
        #[cfg(test)]
        owned_deferred_before_drain(&mut owned);
        if let Err(error) = owned.drain() {
            return Err(owned.refuse(error));
        }
        if owned.cleanup().pidfd.is_none() {
            return Err(owned.refuse(OwnedRunFailure::Startup(StartupError::Protocol)));
        }
        Ok(OwnedDeferredContainerRun { inner: owned })
    }

    /// Runs a function in a new process, publishes its result, and only then
    /// drops a child-owned cleanup value.
    ///
    /// The returned handle owns the mandatory wait for the child. Callers may
    /// inspect the provisional value while doing independent work, but can
    /// only take ownership of it through
    /// [`DeferredContainerRun::finalize`], which rejects an unsuccessful child
    /// exit. Dropping the handle still reaps the child, but yields no value.
    ///
    /// A caller therefore cannot accidentally destructure the value away from
    /// the mandatory cleanup check:
    ///
    /// ```compile_fail
    /// use reverie_process::Container;
    /// let (value, cleanup) = Container::new()
    ///     .run_with_deferred_drop(|| (42, ()))
    ///     .unwrap();
    /// ```
    ///
    /// This has the same fork-safety requirements as [`Container::run`].
    pub fn run_with_deferred_drop<F, T, D>(
        &mut self,
        mut f: F,
    ) -> Result<DeferredContainerRun<T>, RunError>
    where
        F: FnMut() -> (T, D),
        T: Serialize + DeserializeOwned,
    {
        let clone_flags = self.namespace.bits() | libc::SIGCHLD;
        let uid_map = &make_id_map(&self.uid_map);
        let gid_map = &make_id_map(&self.gid_map);
        let context = ChildContext {
            stdin: None,
            stdout: None,
            stderr: None,
            uid_map,
            gid_map,
            seccomp_fd: None,
        };
        let (mut reader, writer) = pipe()?;
        let writer_fd = writer.as_raw_fd();
        let mut stack = child_stack()?;

        #[cfg(feature = "nightly")]
        let output_capture = std::io::set_output_capture(None);

        let result = clone_with_stack(
            || {
                let (value, deferred) = match self.setup(&context, &mut []) {
                    Ok(()) => {
                        let (value, deferred) = f();
                        (Ok(value), Some(deferred))
                    }
                    Err(error) => (Err(error), None),
                };
                let mut writer = std::io::BufWriter::new(Fd::new(writer_fd));
                bincode::serde::encode_into_std_write(
                    &value,
                    &mut writer,
                    bincode::config::legacy(),
                )
                .expect("Failed to serialize return value");
                writer.flush().expect("Failed to flush return value");
                drop(writer);
                drop(deferred);
                0
            },
            clone_flags,
            &mut stack,
        );

        #[cfg(feature = "nightly")]
        std::io::set_output_capture(output_capture);

        let child = WaitGuard::new(result?);
        drop(writer);

        let mut buf = Vec::new();
        match reader.read_to_end(&mut buf) {
            Ok(0) => Err(RunError::ExitStatus(child.wait()?)),
            Ok(n) => {
                let value: Result<T, Error> =
                    bincode::serde::decode_from_slice(&buf[0..n], bincode::config::legacy())
                        .unwrap()
                        .0;
                Ok(DeferredContainerRun {
                    value: Some(value.map_err(RunError::Spawn)?),
                    child,
                })
            }
            Err(error) => panic!("Got unexpected error: {error}"),
        }
    }
}

/// Maximum number of owned descriptors transferred by one container startup.
pub const MAX_STARTUP_FDS: usize = 8;

/// Failure of the finite container startup exchange.
#[derive(
    thiserror::Error,
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    serde::Deserialize
)]
pub enum StartupError {
    /// Container namespace/filesystem/filter setup failed.
    #[error("container setup failed: {0}")]
    Setup(Error),
    /// A startup syscall failed.
    #[error("startup syscall failed: {0}")]
    Io(Errno),
    /// The caller supplied a zero or unrepresentable startup timeout.
    #[error("startup timeout must be positive and representable")]
    InvalidTimeout,
    /// The single monotonic startup deadline elapsed.
    #[error("startup deadline elapsed")]
    TimedOut,
    /// A callback refused startup.
    #[error("startup callback refused")]
    Refused,
    /// The peer closed its endpoint before completing the exchange.
    #[error("startup peer closed prematurely")]
    PeerClosed,
    /// A frame, phase, descriptor count or result encoding was invalid.
    #[error("invalid startup or result protocol")]
    Protocol,
    /// The child exited before publishing its ordinary result.
    #[error("child exited before publishing its result")]
    MissingResult,
}

impl From<Errno> for StartupError {
    fn from(error: Errno) -> Self {
        Self::Io(error)
    }
}

/// A startup failure together with the actual owned-child cleanup outcome.
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum StartupRunError {
    /// Failure before a child was successfully cloned.
    #[error("before clone: {0}")]
    BeforeClone(StartupError),
    /// Failure after clone; the child was reaped with this actual status.
    #[error("{cause}; child terminal status: {status:?}")]
    Child {
        /// Original startup or result failure.
        cause: StartupError,
        /// Actual status returned by waitpid, not an inferred success.
        status: ExitStatus,
    },
    /// Cleanup itself failed; no terminal status is claimed.
    #[error("{cause}; child cleanup failed: {errno}")]
    Cleanup {
        /// Original startup or result failure.
        cause: StartupError,
        /// Actual cancellation/wait error.
        errno: Errno,
    },
}

#[derive(Default)]
struct StartupFds {
    values: [Option<std::os::fd::OwnedFd>; MAX_STARTUP_FDS],
    len: usize,
}

impl StartupFds {
    fn push(&mut self, fd: std::os::fd::OwnedFd) -> Result<(), StartupError> {
        if self.len == MAX_STARTUP_FDS {
            return Err(StartupError::Protocol);
        }
        self.values[self.len] = Some(fd);
        self.len += 1;
        Ok(())
    }
}

/// Child-only setup context, constructed after namespace/filesystem setup.
///
/// It is neither clonable nor serializable. Transferred descriptors are sent
/// once with SCM_RIGHTS, then the child's originals are closed before seccomp.
/// This context creates no worker and carries no authority to emit capture data.
pub struct ChildStartContext {
    deadline: std::time::Instant,
    descriptors: StartupFds,
    failure: Option<StartupError>,
}

impl ChildStartContext {
    /// The same finite monotonic deadline used by both endpoints.
    pub fn deadline(&self) -> std::time::Instant {
        self.deadline
    }

    /// Transfers ownership of a descriptor to the parent startup callback.
    /// Exceeding [`MAX_STARTUP_FDS`] refuses startup and closes the supplied FD.
    pub fn transfer_fd(&mut self, fd: std::os::fd::OwnedFd) -> Result<(), StartupError> {
        let result = self.descriptors.push(fd);
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }
}

/// Parent-only startup context bound to this invocation's unreaped child.
///
/// The PID is a locator; the borrowed pidfd and privately held wait guard bind
/// the actual child generation. Constructors are private. No raw PID or FD
/// supplied by a caller can manufacture this context.
pub struct ParentStartContext<'a> {
    child_pid: Pid,
    child_pidfd: std::os::fd::BorrowedFd<'a>,
    deadline: std::time::Instant,
    descriptors: StartupFds,
}

impl ParentStartContext<'_> {
    /// The owned child PID in the parent's namespace; do not reap it separately.
    pub fn child_pid(&self) -> Pid {
        self.child_pid
    }

    /// Borrows the owned child generation's pidfd for identity-sensitive setup.
    pub fn child_pidfd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.child_pidfd
    }

    /// The same finite monotonic deadline used by both endpoints.
    pub fn deadline(&self) -> std::time::Instant {
        self.deadline
    }

    /// Number of descriptors supplied by the child (at most [`MAX_STARTUP_FDS`]).
    pub fn descriptor_count(&self) -> usize {
        self.descriptors.len
    }

    /// Takes one received descriptor exactly once. Untaken descriptors close
    /// when this context is dropped. An out-of-range index returns `None`.
    pub fn take_fd(&mut self, index: usize) -> Option<std::os::fd::OwnedFd> {
        self.descriptors.values.get_mut(index)?.take()
    }
}

#[derive(Clone, Copy)]
struct StartupChildIo {
    parent_fd: i32,
    child_fd: i32,
    reader_fd: i32,
    writer_fd: i32,
    deadline: std::time::Instant,
}

// A fixed, private readiness exchange, not an evidence/event transport. The
// sole pair is created before clone; each branch closes the other endpoint.
const STARTUP_REQUEST: u8 = 1;
const STARTUP_READY: u8 = 2;
const STARTUP_FAILURE: u8 = 4;
const STARTUP_FRAME_SIZE: usize = 64;

struct StartupSocket {
    fd: Fd,
    deadline: std::time::Instant,
}

impl StartupSocket {
    fn pair(deadline: std::time::Instant) -> Result<(Self, Self), StartupError> {
        let mut pair = [-1; 2];
        Errno::result(unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                pair.as_mut_ptr(),
            )
        })?;
        Ok((
            Self {
                fd: Fd::new(pair[0]),
                deadline,
            },
            Self {
                fd: Fd::new(pair[1]),
                deadline,
            },
        ))
    }

    fn poll(&self, events: libc::c_short) -> Result<(), StartupError> {
        loop {
            let remaining = self
                .deadline
                .checked_duration_since(std::time::Instant::now())
                .filter(|value| !value.is_zero())
                .ok_or(StartupError::TimedOut)?;
            let millis = remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let mut fd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events,
                revents: 0,
            };
            match Errno::result(unsafe { libc::poll(&mut fd, 1, millis) }) {
                Ok(0) | Err(Errno::EINTR) => continue,
                Ok(_) if fd.revents & libc::POLLNVAL != 0 => {
                    return Err(StartupError::Io(Errno::EBADF));
                }
                Ok(_) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn send_bytes(&self, bytes: &[u8], fds: &StartupFds) -> Result<(), StartupError> {
        // The first successful send carries rights exactly once, even when its
        // data is partial. Subsequent sends carry only remaining frame bytes.
        let mut ancillary = [0usize; 16];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        if fds.len != 0 {
            message.msg_control = ancillary.as_mut_ptr().cast();
            message.msg_controllen =
                unsafe { libc::CMSG_SPACE((fds.len * std::mem::size_of::<i32>()) as u32) as usize };
            assert!(message.msg_controllen <= std::mem::size_of_val(&ancillary));
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len =
                    libc::CMSG_LEN((fds.len * std::mem::size_of::<i32>()) as u32) as usize;
                let data = libc::CMSG_DATA(header).cast::<i32>();
                for index in 0..fds.len {
                    data.add(index)
                        .write(fds.values[index].as_ref().unwrap().as_raw_fd());
                }
            }
        }
        let mut offset = 0;
        while offset < bytes.len() {
            self.poll(libc::POLLOUT)?;
            let mut iov = libc::iovec {
                iov_base: bytes[offset..].as_ptr().cast_mut().cast(),
                iov_len: bytes.len() - offset,
            };
            #[cfg(test)]
            if STARTUP_TEST_FAULT.with(|fault| fault.get()) == StartupTestFault::Fragmented {
                iov.iov_len = 1;
            }
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            match Errno::result(unsafe {
                libc::sendmsg(self.fd.as_raw_fd(), &message, libc::MSG_NOSIGNAL)
            }) {
                Ok(0) => return Err(StartupError::Protocol),
                Ok(size) => {
                    offset += size as usize;
                    message.msg_control = std::ptr::null_mut();
                    message.msg_controllen = 0;
                }
                Err(Errno::EINTR | Errno::EAGAIN) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn send(
        &self,
        phase: u8,
        fds: &StartupFds,
        failure: Option<StartupError>,
    ) -> Result<(), StartupError> {
        let mut frame = [0u8; STARTUP_FRAME_SIZE];
        frame[..4].copy_from_slice(b"RVS1");
        frame[4] = phase;
        frame[5] = fds.len as u8;
        if let Some(error) = failure {
            frame[6] = bincode::serde::encode_into_slice(
                error,
                &mut frame[8..],
                bincode::config::legacy(),
            )
            .map_err(|_| StartupError::Protocol)? as u8;
        }
        #[cfg(test)]
        if let Some(result) = self.inject_test_fault(phase, &frame, fds) {
            return result;
        }
        self.send_bytes(&frame, fds)
    }

    fn receive(&self, phase: Option<u8>) -> Result<StartupFds, StartupError> {
        use std::os::fd::FromRawFd;
        let mut frame = [0u8; STARTUP_FRAME_SIZE];
        let mut offset = 0;
        let mut fds = StartupFds::default();
        loop {
            self.poll(libc::POLLIN)?;
            let mut ancillary = [0usize; 16];
            let capacity = if phase.is_none() {
                1
            } else {
                frame.len() - offset
            };
            let mut iov = libc::iovec {
                iov_base: frame[offset..].as_mut_ptr().cast(),
                iov_len: capacity,
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = ancillary.as_mut_ptr().cast();
            message.msg_controllen = unsafe {
                libc::CMSG_SPACE((MAX_STARTUP_FDS * std::mem::size_of::<i32>()) as u32) as usize
            };
            assert!(message.msg_controllen <= std::mem::size_of_val(&ancillary));
            let size = match Errno::result(unsafe {
                libc::recvmsg(self.fd.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC)
            }) {
                Ok(size) => size as usize,
                Err(Errno::EINTR | Errno::EAGAIN) => continue,
                Err(error) => return Err(error.into()),
            };
            let mut malformed = message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
            let previous_fds = fds.len;
            // Own every received FD before checking bytes/phase, including
            // trailing data and EOF. Linux closes rights lost to MSG_CTRUNC.
            unsafe {
                let mut header = libc::CMSG_FIRSTHDR(&message);
                while !header.is_null() {
                    if (*header).cmsg_level == libc::SOL_SOCKET
                        && (*header).cmsg_type == libc::SCM_RIGHTS
                        && (*header).cmsg_len >= libc::CMSG_LEN(0) as usize
                    {
                        let bytes = (*header).cmsg_len - libc::CMSG_LEN(0) as usize;
                        malformed |= !bytes.is_multiple_of(std::mem::size_of::<i32>());
                        let data = libc::CMSG_DATA(header).cast::<i32>();
                        for index in 0..bytes / std::mem::size_of::<i32>() {
                            let fd = std::os::fd::OwnedFd::from_raw_fd(data.add(index).read());
                            if fds.push(fd).is_err() {
                                malformed = true;
                            }
                        }
                    } else {
                        malformed = true;
                    }
                    header = libc::CMSG_NXTHDR(&message, header);
                }
            }
            if malformed
                || (fds.len != previous_fds && (offset != 0 || phase != Some(STARTUP_REQUEST)))
            {
                return Err(StartupError::Protocol);
            }
            if size == 0 {
                // SOCK_STREAM has no zero-length data messages. Unlike
                // SEQPACKET, this is genuine EOF, never an empty packet.
                return if phase.is_none() && fds.len == 0 {
                    Ok(fds)
                } else if offset == 0 && fds.len == 0 {
                    Err(StartupError::PeerClosed)
                } else {
                    Err(StartupError::Protocol)
                };
            }
            if phase.is_none() {
                return Err(StartupError::Protocol);
            }
            offset += size;
            if offset < frame.len() {
                continue;
            }
            if &frame[..4] != b"RVS1" || frame[5] as usize != fds.len || frame[7] != 0 {
                return Err(StartupError::Protocol);
            }
            if frame[4] == STARTUP_FAILURE
                && fds.len == 0
                && frame[6] != 0
                && frame[6] as usize <= frame.len() - 8
            {
                let end = 8 + frame[6] as usize;
                let (error, used) = bincode::serde::decode_from_slice::<StartupError, _>(
                    &frame[8..end],
                    bincode::config::legacy(),
                )
                .map_err(|_| StartupError::Protocol)?;
                if used != end - 8 || frame[end..].iter().any(|byte| *byte != 0) {
                    return Err(StartupError::Protocol);
                }
                return Err(error);
            }
            if phase != Some(frame[4])
                || frame[6..].iter().any(|byte| *byte != 0)
                || (frame[4] != STARTUP_REQUEST && fds.len != 0)
            {
                return Err(StartupError::Protocol);
            }
            return Ok(fds);
        }
    }

    fn close_write(&self) -> Result<(), StartupError> {
        Errno::result(unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_WR) })?;
        Ok(())
    }
}

// Test-only wire corruption. It substitutes bytes at the actual private send
// boundary; it never bypasses the production decoder, readiness or workload
// gate. Thread-local state keeps unrelated container tests independent.
#[cfg(test)]
#[derive(Copy, Clone, Eq, PartialEq)]
enum StartupTestFault {
    None,
    Fragmented,
    RequestEmptyTrailing,
    RequestDuplicate,
    RequestMalformed,
    RequestTrailingRights,
    PermissionEmptyTrailing,
    PermissionDuplicate,
    PermissionMalformed,
    PermissionTrailingRights,
    ObservePermissionLate,
}

#[cfg(test)]
std::thread_local! {
    static STARTUP_TEST_FAULT: std::cell::Cell<StartupTestFault> = const { std::cell::Cell::new(StartupTestFault::None) };
}

#[cfg(test)]
impl StartupSocket {
    fn inject_test_fault(
        &self,
        phase: u8,
        frame: &[u8],
        fds: &StartupFds,
    ) -> Option<Result<(), StartupError>> {
        use StartupTestFault::*;
        let fault = STARTUP_TEST_FAULT.with(|value| value.get());
        let request = phase == STARTUP_REQUEST;
        let permission = phase == STARTUP_READY;
        if (request && fault == RequestEmptyTrailing)
            || (permission && fault == PermissionEmptyTrailing)
        {
            return Some({
                assert_eq!(
                    unsafe {
                        libc::send(self.fd.as_raw_fd(), std::ptr::null(), 0, libc::MSG_NOSIGNAL)
                    },
                    0
                );
                self.send_bytes(b"X", &StartupFds::default())
            });
        }
        if (request && fault == RequestMalformed) || (permission && fault == PermissionMalformed) {
            let mut bad = frame.to_vec();
            bad[0] ^= 1;
            return Some(self.send_bytes(&bad, fds));
        }
        if (request && fault == RequestDuplicate) || (permission && fault == PermissionDuplicate) {
            return Some(
                self.send_bytes(frame, fds)
                    .and_then(|()| self.send_bytes(frame, fds)),
            );
        }
        if (request && fault == RequestTrailingRights)
            || (permission && fault == PermissionTrailingRights)
        {
            return Some((|| {
                self.send_bytes(frame, fds)?;
                let mut trailing = StartupFds::default();
                trailing.push(std::fs::File::open("/dev/null").unwrap().into())?;
                self.send_bytes(b"X", &trailing)
            })());
        }
        Option::None
    }
}

/// An observation of the original child, never an inferred successful exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildCleanupObservation {
    /// The original child has not yielded a terminal observation yet.
    Pending,
    /// The exclusive wait obtained this actual terminal status.
    Reaped(ExitStatus),
    /// The pidfd proves exit, but another reaper consumed the wait status.
    ExitedWithoutWaitStatus,
    /// Cleanup failed without proving physical termination.
    Unknown,
}

/// Retains the atomically acquired child identity and exclusive wait obligation.
///
/// No other thread/handler may reap this child or close its private pidfd.
/// Explicit waits are bounded; Drop cancels and waits and can block indefinitely
/// on an uninterruptible child or persistent inability to observe its exit.
/// Such failures require outer process supervision, never a detached reaper.
#[derive(Debug)]
pub struct OwnedContainerCleanup {
    pid: Pid,
    wait_owned: bool,
    pidfd: Option<std::os::fd::OwnedFd>,
    observation: ChildCleanupObservation,
    last_error: Option<Errno>,
    #[cfg(test)]
    signal_error_once: Option<Errno>,
    #[cfg(test)]
    wait_error_once: Option<Errno>,
    #[cfg(test)]
    cancellation_observed: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl OwnedContainerCleanup {
    fn new(child: super::clone::OwnedClone) -> Self {
        Self {
            pid: child.pid,
            wait_owned: true,
            pidfd: child.pidfd,
            observation: ChildCleanupObservation::Pending,
            last_error: None,
            #[cfg(test)]
            signal_error_once: OWNED_STARTUP_CANCEL_ERROR.with(|error| error.take()),
            #[cfg(test)]
            wait_error_once: None,
            #[cfg(test)]
            cancellation_observed: None,
        }
    }

    /// The original PID, for diagnostics only; do not signal or reap it separately.
    pub fn child_pid(&self) -> Pid {
        self.pid
    }
    /// The last actual observation; a timeout does not fabricate a wait status.
    pub fn observation(&self) -> ChildCleanupObservation {
        self.observation
    }
    /// The most recent cleanup error, retained even after later physical exit.
    pub fn last_error(&self) -> Option<Errno> {
        self.last_error
    }

    fn settled(&self) -> bool {
        matches!(
            self.observation,
            ChildCleanupObservation::Reaped(_) | ChildCleanupObservation::ExitedWithoutWaitStatus
        )
    }

    fn observe_wait(&mut self) -> Result<(), Errno> {
        if !self.wait_owned {
            return Ok(());
        }
        #[cfg(test)]
        if let Some(error) = self.wait_error_once.take() {
            return Err(error);
        }
        let mut status = 0;
        match Errno::result(unsafe { libc::waitpid(self.pid.as_raw(), &mut status, libc::WNOHANG) })
        {
            Ok(0) => (),
            Ok(pid) => {
                assert_eq!(pid, self.pid.as_raw());
                self.wait_owned = false;
                self.observation = ChildCleanupObservation::Reaped(ExitStatus::from_raw(status));
            }
            Err(Errno::ECHILD) => {
                // Never issue another numeric-PID wait after losing ownership.
                self.wait_owned = false;
                self.last_error = Some(Errno::ECHILD);
                self.observation = ChildCleanupObservation::Unknown;
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Observes the actual child until the absolute deadline, retaining ownership.
    pub fn wait_until(&mut self, deadline: std::time::Instant) -> ChildCleanupObservation {
        loop {
            if self.settled() {
                return self.observation;
            }
            match self.observe_wait() {
                Ok(()) => (),
                Err(Errno::EINTR) => {
                    self.last_error = Some(Errno::EINTR);
                    if std::time::Instant::now() < deadline {
                        continue;
                    }
                }
                Err(error) => {
                    self.last_error = Some(error);
                    self.observation = ChildCleanupObservation::Unknown;
                    return self.observation;
                }
            }
            if self.settled() {
                return self.observation;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let milliseconds = remaining
                .as_millis()
                .saturating_add(u128::from(!remaining.is_zero()))
                .min(10) as i32;
            let mut poll = libc::pollfd {
                fd: self.pidfd.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            };
            match Errno::result(unsafe { libc::poll(&mut poll, 1, milliseconds) }) {
                Ok(_) => {
                    if poll.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
                        self.last_error = Some(Errno::EBADF);
                        self.observation = ChildCleanupObservation::Unknown;
                        return self.observation;
                    }
                    if !self.wait_owned && poll.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                        self.observation = ChildCleanupObservation::ExitedWithoutWaitStatus;
                        return self.observation;
                    }
                }
                Err(Errno::EINTR) => {
                    self.last_error = Some(Errno::EINTR);
                    #[cfg(test)]
                    OWNED_POLL_INTERRUPTED.fetch_add(1, std::sync::atomic::Ordering::Release);
                }
                Err(error) => {
                    self.last_error = Some(error);
                    self.observation = ChildCleanupObservation::Unknown;
                    return self.observation;
                }
            }
            if std::time::Instant::now() >= deadline {
                // One nonblocking wait after readiness keeps its real status
                // when exit raced with the deadline. It never extends the wait.
                if let Err(error) = self.observe_wait() {
                    self.last_error = Some(error);
                    self.observation = ChildCleanupObservation::Unknown;
                }
                return self.observation;
            }
        }
    }

    fn signal_cancel(&mut self) -> Result<(), Errno> {
        #[cfg(test)]
        if let Some(error) = self.signal_error_once.take() {
            return Err(error);
        }
        let fd = self.pidfd.as_ref().ok_or(Errno::EBADF)?;
        Errno::result(unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        })
        .map(|_| ())
    }

    /// Sends cancellation through the held pidfd, then observes until the deadline.
    /// ESRCH alone is not evidence of termination. Errors retain this owner.
    pub fn cancel_and_wait_until(
        &mut self,
        deadline: std::time::Instant,
    ) -> ChildCleanupObservation {
        if self.settled() {
            return self.observation;
        }
        match self.signal_cancel() {
            Ok(()) => (),
            Err(error) => {
                self.last_error = Some(error);
                // A refused signal does not prevent independent child exit.
                // Always observe the original wait/pidfd, retaining the errno.
                // Missing atomic output never permits numeric signalling.
            }
        }
        #[cfg(test)]
        if let Some(observed) = &self.cancellation_observed {
            observed.store(true, std::sync::atomic::Ordering::Release);
        }
        self.wait_until(deadline)
    }
}

impl Drop for OwnedContainerCleanup {
    fn drop(&mut self) {
        while !self.settled() {
            self.cancel_and_wait_until(
                std::time::Instant::now() + std::time::Duration::from_millis(100),
            );
            if !self.settled() {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static OWNED_STARTUP_CANCEL_ERROR: std::cell::Cell<Option<Errno>> = const { std::cell::Cell::new(None) };
    static OWNED_DEFERRED_DRAIN_HOOK: std::cell::Cell<Option<fn(RawFd)>> = const { std::cell::Cell::new(None) };
    static OWNED_RESULT_PIPE_CAPACITY: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn owned_deferred_before_drain<T>(owned: &mut OwnedFinalization<T>) {
    if let Some(hook) = OWNED_DEFERRED_DRAIN_HOOK.with(|hook| hook.take()) {
        hook(owned.reader.as_ref().unwrap().as_raw_fd());
    }
}

#[cfg(test)]
static OWNED_POLL_INTERRUPTED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The original failure, separate from subsequent cleanup observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedRunFailure {
    /// The caller explicitly cancelled this run. External error details remain
    /// with that caller; later successful child exit cannot erase cancellation.
    Cancelled,
    /// Startup or the child's encoded startup/setup refusal.
    Startup(StartupError),
    /// The actual result-reader syscall failed; partial bytes remain retained.
    ResultRead(Errno),
    /// The real child returned an unsuccessful terminal status.
    ChildStatus(ExitStatus),
    /// Cleanup failed before an actual terminal status could be obtained.
    Cleanup(Errno),
    /// Physical exit is established, but a competing reaper lost the status.
    WaitStatusUnavailable,
}

/// An owned startup or result-acquisition refusal. Every post-clone failure
/// retains the real child, including failures from an owned deferred workload.
#[derive(Debug)]
pub enum StartupOwnedFailure<T> {
    /// The clone did not create a child.
    BeforeClone {
        /// The original refusal.
        cause: StartupError,
    },
    /// A child exists; inspect/retry/dispose its retained owner explicitly.
    AfterClone {
        /// The original refusal, independent of cleanup success or failure.
        cause: OwnedRunFailure,
        /// Original child, open result FD if any, and exact partial bytes.
        run: OwnedFinalization<T>,
    },
}

/// Encoded bytes and the child, retained through pending or failed cleanup.
/// No generic result value has been deserialized in the parent.
#[must_use = "retain or settle the actual child before releasing external owners"]
pub struct OwnedFinalization<T> {
    child: Option<OwnedContainerCleanup>,
    reader: Option<Fd>,
    bytes: Vec<u8>,
    eof: bool,
    failure: Option<OwnedRunFailure>,
    marker: std::marker::PhantomData<fn() -> T>,
}

impl<T> std::fmt::Debug for OwnedFinalization<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedFinalization")
            .field("child", &self.child)
            .field("bytes", &self.bytes.len())
            .field("eof", &self.eof)
            .field("failure", &self.failure)
            .finish()
    }
}

impl<T> OwnedFinalization<T> {
    fn new(child: OwnedContainerCleanup, reader: Fd) -> Self {
        Self {
            child: Some(child),
            reader: Some(reader),
            bytes: Vec::new(),
            eof: false,
            failure: None,
            marker: std::marker::PhantomData,
        }
    }
    /// Exact bytes received so far, which are not a decoded result or authority.
    pub fn provisional_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Whether an actual EOF completed result acquisition.
    pub fn result_eof(&self) -> bool {
        self.eof
    }
    /// Whether cleanup abandoned an unread result reader because a failed
    /// owner lacked a pidfd. Collected bytes and the first failure stay intact;
    /// abandonment is not EOF, cancellation, or proof of child termination.
    pub fn result_reader_abandoned(&self) -> bool {
        !self.eof && self.reader.is_none()
    }
    /// Borrows diagnostic identity and cleanup observations without disarming ownership.
    pub fn cleanup(&self) -> &OwnedContainerCleanup {
        self.child.as_ref().unwrap()
    }
    /// The frozen original failure, if one was observed.
    pub fn failure(&self) -> Option<OwnedRunFailure> {
        self.failure
    }

    fn fail(
        mut self,
        cause: OwnedRunFailure,
        deadline: std::time::Instant,
    ) -> StartupOwnedFailure<T> {
        self.failure = Some(cause);
        self.child.as_mut().unwrap().cancel_and_wait_until(deadline);
        StartupOwnedFailure::AfterClone { cause, run: self }
    }
    fn refuse(mut self, cause: OwnedRunFailure) -> StartupOwnedFailure<T> {
        self.failure = Some(cause);
        StartupOwnedFailure::AfterClone { cause, run: self }
    }

    fn drain(&mut self) -> Result<(), OwnedRunFailure> {
        match self.reader.as_mut().unwrap().read_to_end(&mut self.bytes) {
            Ok(_) => {
                self.eof = true;
                self.reader.take();
                if self.bytes.is_empty() {
                    Err(OwnedRunFailure::Startup(StartupError::MissingResult))
                } else {
                    Ok(())
                }
            }
            Err(error) => Err(OwnedRunFailure::ResultRead(Errno::new(
                error.raw_os_error().unwrap_or(libc::EIO),
            ))),
        }
    }
    /// Retries observation/cancellation while preserving bytes and the original
    /// child identity, with unread-reader abandonment only as described below.
    /// A previously failed result stays failed even if cleanup later succeeds.
    /// If that failed owner has no pidfd, close its unread result reader before
    /// waiting: retaining it could block the child serializer forever while
    /// waiting for that same child. This preserves the original wait and bytes,
    /// but permits the child to observe a broken pipe. It does not guarantee
    /// arbitrary workers or a child ignoring write failures will terminate.
    pub fn retry_until(mut self, deadline: std::time::Instant) -> OwnedFinalize<T> {
        self.abandon_unread_result_without_pidfd();
        let child = self.child.as_mut().unwrap();
        if let Some(cause) = self.failure {
            child.cancel_and_wait_until(deadline);
            return OwnedFinalize::Failed {
                cause,
                cleanup: self,
            };
        }
        match child.wait_until(deadline) {
            ChildCleanupObservation::Reaped(status) if status.success() => {
                assert!(self.eof);
                self.child.take();
                OwnedFinalize::Complete(OwnedReapedResult {
                    bytes: std::mem::take(&mut self.bytes),
                    status,
                    marker: std::marker::PhantomData,
                })
            }
            ChildCleanupObservation::Reaped(status) => {
                let cause = OwnedRunFailure::ChildStatus(status);
                self.failure = Some(cause);
                OwnedFinalize::Failed {
                    cause,
                    cleanup: self,
                }
            }
            ChildCleanupObservation::ExitedWithoutWaitStatus => {
                let cause = OwnedRunFailure::WaitStatusUnavailable;
                self.failure = Some(cause);
                OwnedFinalize::Failed {
                    cause,
                    cleanup: self,
                }
            }
            ChildCleanupObservation::Unknown => {
                if let Some(error) = child.last_error() {
                    let cause = OwnedRunFailure::Cleanup(error);
                    self.failure = Some(cause);
                    OwnedFinalize::Failed {
                        cause,
                        cleanup: self,
                    }
                } else {
                    OwnedFinalize::Pending(self)
                }
            }
            ChildCleanupObservation::Pending => OwnedFinalize::Pending(self),
        }
    }

    /// Cancels through the original owner up to the absolute deadline.
    /// An earlier failure takes precedence; otherwise cancellation becomes the
    /// sticky failure even if C subsequently exits successfully. A returned
    /// failed owner can still be pending cleanup and must be retained or retried.
    pub fn cancel_until(mut self, deadline: std::time::Instant) -> OwnedFinalize<T> {
        self.failure.get_or_insert(OwnedRunFailure::Cancelled);
        self.retry_until(deadline)
    }

    fn abandon_unread_result_without_pidfd(&mut self) {
        if self.failure.is_some()
            && self
                .child
                .as_ref()
                .is_some_and(|child| child.pidfd.is_none())
        {
            self.reader.take();
        }
    }
}

impl<T> Drop for OwnedFinalization<T> {
    fn drop(&mut self) {
        // An unread serializer cannot make progress while this owner both
        // keeps its reader open and waits without a cancellation capability.
        // Keep the original child wait; only abandon that pipe endpoint.
        self.abandon_unread_result_without_pidfd();
        drop(self.child.take());
        self.reader.take();
    }
}

/// A complete encoded result whose original child has not yet been settled.
#[derive(Debug)]
#[must_use = "the actual child must be finalized before decoding"]
pub struct OwnedDeferredContainerRun<T> {
    inner: OwnedFinalization<T>,
}
impl<T> OwnedDeferredContainerRun<T> {
    /// Bytes are provisional until actual child settlement and decoding succeed.
    pub fn provisional_bytes(&self) -> &[u8] {
        self.inner.provisional_bytes()
    }
    /// Borrows the actual retained child's diagnostic identity.
    pub fn cleanup(&self) -> &OwnedContainerCleanup {
        self.inner.cleanup()
    }
    /// Observes the real child up to the deadline, retaining ownership on failure.
    pub fn finalize_until(self, deadline: std::time::Instant) -> OwnedFinalize<T> {
        self.inner.retry_until(deadline)
    }

    /// Records explicit cancellation and makes a bounded attempt through the
    /// same child capability, retaining the complete result bytes on failure.
    pub fn cancel_until(self, deadline: std::time::Instant) -> OwnedFinalize<T> {
        self.inner.cancel_until(deadline)
    }
}

/// The distinction between real completion, persistent failure and an owned pending wait.
#[derive(Debug)]
pub enum OwnedFinalize<T> {
    /// Actual successful child status; result bytes are still encoded.
    Complete(OwnedReapedResult<T>),
    /// Frozen failure and the still-owned resources, including actual cleanup state.
    Failed {
        /// Original cause.
        cause: OwnedRunFailure,
        /// Owned child and result resources.
        cleanup: OwnedFinalization<T>,
    },
    /// The observation deadline elapsed without relinquishing the original child.
    Pending(OwnedFinalization<T>),
}

/// A successful child wait plus original encoded bytes. Decode is deliberately separate.
#[derive(Debug)]
pub struct OwnedReapedResult<T> {
    bytes: Vec<u8>,
    status: ExitStatus,
    marker: std::marker::PhantomData<fn() -> T>,
}
impl<T> OwnedReapedResult<T> {
    /// The actual successful child status.
    pub fn status(&self) -> ExitStatus {
        self.status
    }
    /// The original complete wire bytes.
    pub fn encoded_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl<T: DeserializeOwned> OwnedReapedResult<T> {
    /// Decodes the entire original value only after actual child termination.
    /// Callers owning external workers/factories must settle those before this call.
    pub fn decode(self) -> Result<T, OwnedDecodeFailure> {
        let (cause, detail) = match bincode::serde::decode_from_slice::<Result<T, StartupError>, _>(
            &self.bytes,
            bincode::config::legacy(),
        ) {
            Ok((Ok(value), used)) if used == self.bytes.len() => return Ok(value),
            Ok((Err(error), used)) if used == self.bytes.len() => {
                (OwnedRunFailure::Startup(error), None)
            }
            Ok(_) => (
                OwnedRunFailure::Startup(StartupError::Protocol),
                Some("trailing result bytes".to_owned()),
            ),
            Err(error) => (
                OwnedRunFailure::Startup(StartupError::Protocol),
                Some(error.to_string()),
            ),
        };
        Err(OwnedDecodeFailure {
            cause,
            detail,
            bytes: self.bytes,
            status: self.status,
        })
    }
}

/// Decode refusal retaining the complete bytes and genuine child status.
#[derive(Debug)]
pub struct OwnedDecodeFailure {
    cause: OwnedRunFailure,
    detail: Option<String>,
    bytes: Vec<u8>,
    status: ExitStatus,
}
impl OwnedDecodeFailure {
    /// The original typed refusal.
    pub fn cause(&self) -> OwnedRunFailure {
        self.cause
    }
    /// An actual decoding diagnostic when available.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
    /// Unchanged bytes which caused the refusal.
    pub fn encoded_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Actual successful child status, which does not erase a decoding failure.
    pub fn status(&self) -> ExitStatus {
        self.status
    }
}

// Owns cancellation only during startup/result acquisition. Old WaitGuard and
// deferred-result drop semantics remain unchanged after successful acquisition.
struct StartupChild {
    wait: Option<WaitGuard>,
    pidfd: Option<Fd>,
}

impl StartupChild {
    fn cancel(&mut self) -> Result<ExitStatus, Errno> {
        let wait = self.wait.as_ref().unwrap();
        let result = match &self.pidfd {
            Some(fd) => Errno::result(unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            })
            .map(|_| ()),
            // Before pidfd_open completes, this is still the unreaped child
            // returned by clone. Callers must not install an auto-reaper or
            // wait for this invocation's child from another thread/handler.
            None => Errno::result(unsafe { libc::kill(wait.0.unwrap().as_raw(), libc::SIGKILL) })
                .map(|_| ()),
        };
        match result {
            Ok(()) | Err(Errno::ESRCH) => (),
            Err(error) => return Err(error),
        }
        self.wait.take().unwrap().wait()
    }

    fn fail(&mut self, cause: StartupError) -> StartupRunError {
        match self.cancel() {
            Ok(status) => StartupRunError::Child { cause, status },
            Err(errno) => StartupRunError::Cleanup { cause, errno },
        }
    }

    fn into_wait(mut self) -> WaitGuard {
        self.wait.take().unwrap()
    }
}

impl Drop for StartupChild {
    fn drop(&mut self) {
        if self.wait.is_some() {
            let _ = self.cancel();
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
        self.wait_inner()
    }

    fn wait_inner(&mut self) -> Result<ExitStatus, Errno> {
        let pid = self.0.expect("child wait guard has already been consumed");
        #[cfg(test)]
        let instrumented_wait = WAITPID_TEST_PID.load(Ordering::Acquire) == pid.as_raw();
        let mut status = 0;
        loop {
            #[cfg(test)]
            if instrumented_wait {
                WAITPID_ENTERED.store(true, Ordering::Release);
            }
            match Errno::result(unsafe { libc::waitpid(pid.as_raw(), &mut status, 0) }) {
                Ok(ret) => {
                    assert_eq!(ret, pid.as_raw());
                    self.0 = None;
                    return Ok(ExitStatus::from_raw(status));
                }
                Err(Errno::EINTR) => {
                    #[cfg(test)]
                    {
                        if instrumented_wait {
                            WAITPID_INTERRUPTED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(Errno::ECHILD) => {
                    self.0 = None;
                    return Err(Errno::ECHILD);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// A provisional container result whose successful value remains owned by its
/// mandatory cleanup check.
#[must_use = "a deferred container result must be finalized before its value can be returned"]
pub struct DeferredContainerRun<T> {
    value: Option<T>,
    child: WaitGuard,
}

impl<T> DeferredContainerRun<T> {
    /// Borrows the value while the child finishes cleanup.
    pub fn provisional(&self) -> &T {
        self.value.as_ref().expect("provisional value is present")
    }

    /// Waits for cleanup and returns the value only after a successful exit.
    pub fn finalize(self) -> Result<T, RunError> {
        self.finalize_with_status().map(|(value, _status)| value)
    }

    /// Waits for cleanup and returns the value and actual successful child
    /// status. A nonzero/signal status remains [`RunError::ExitStatus`]. This
    /// observes this container child only, not any guest's separate teardown.
    pub fn finalize_with_status(mut self) -> Result<(T, ExitStatus), RunError> {
        let status = self.child.wait()?;
        if !status.success() {
            return Err(RunError::ExitStatus(status));
        }
        Ok((
            self.value.take().expect("provisional value is present"),
            status,
        ))
    }
}

impl Drop for WaitGuard {
    fn drop(&mut self) {
        if self.0.is_some() {
            let _ = self.wait_inner();
        }
    }
}

#[cfg(test)]
static WAITPID_TEST_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
#[cfg(test)]
static WAITPID_ENTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static WAITPID_INTERRUPTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::Instant;

    use nix::sys::signal::SaFlags;
    use nix::sys::signal::SigAction;
    use nix::sys::signal::SigHandler;
    use nix::sys::signal::SigSet;
    use nix::sys::signal::Signal;
    use nix::sys::signal::sigaction;

    use super::*;

    include!("owned_deferred_tests.rs");

    fn owned_complete<T>(handle: OwnedDeferredContainerRun<T>) -> OwnedReapedResult<T> {
        match handle.finalize_until(Instant::now() + Duration::from_secs(2)) {
            OwnedFinalize::Complete(result) => result,
            other => panic!(
                "expected actual successful child settlement: {:?}",
                outcome_kind(&other)
            ),
        }
    }

    fn outcome_kind<T>(outcome: &OwnedFinalize<T>) -> &'static str {
        match outcome {
            OwnedFinalize::Complete(_) => "complete",
            OwnedFinalize::Failed { .. } => "failed",
            OwnedFinalize::Pending(_) => "pending",
        }
    }

    struct OwnedCloneFaultGuard;
    impl OwnedCloneFaultGuard {
        fn install(fault: super::super::clone::OwnedCloneTestFault) -> Self {
            super::super::clone::OWNED_CLONE_FAULT.with(|f| {
                assert_eq!(f.get(), super::super::clone::OwnedCloneTestFault::None);
                f.set(fault);
            });
            Self
        }
    }
    impl Drop for OwnedCloneFaultGuard {
        fn drop(&mut self) {
            super::super::clone::OWNED_CLONE_FAULT
                .with(|f| f.set(super::super::clone::OwnedCloneTestFault::None));
        }
    }

    fn owned_test_pidfd_link(path: &Path) -> bool {
        let Some(link) = path.to_str() else {
            return false;
        };
        link == "anon_inode:[pidfd]"
            || link
                .strip_prefix("pidfd:[")
                .and_then(|suffix| suffix.strip_suffix(']'))
                .is_some_and(|inode| !inode.is_empty() && inode.bytes().all(|b| b.is_ascii_digit()))
    }

    #[test]
    fn owned_startup_atomic_identity_and_complete_decode() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use std::os::fd::AsFd;
        let parent = Pid::this();
        let mut actual_child = None;
        let handle = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |mut context| {
                    actual_child = Some(context.child_pid());
                    assert_ne!(context.child_pid(), parent);
                    let fd = context.child_pidfd().as_raw_fd();
                    let pidfd_link = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
                    assert!(
                        owned_test_pidfd_link(&pidfd_link),
                        "live pidfd: {pidfd_link:?}"
                    );
                    eprintln!("owned pidfd anchor: {pidfd_link:?}");
                    assert_ne!(
                        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                        0
                    );
                    let mut transferred = std::fs::File::from(context.take_fd(0).unwrap());
                    assert!(context.take_fd(0).is_none());
                    let mut text = String::new();
                    transferred.read_to_string(&mut text).unwrap();
                    assert!(text.starts_with(&format!("{} ", context.child_pid())));
                    Ok(())
                },
                &mut |context| {
                    // The freshly created parent pidfd is not an inherited C alias.
                    let aliases = std::fs::read_dir("/proc/self/fd")
                        .unwrap()
                        .filter_map(Result::ok)
                        .filter_map(|e| std::fs::read_link(e.path()).ok())
                        .filter(|p| owned_test_pidfd_link(p))
                        .count();
                    eprintln!("owned child inherited pidfd aliases: {aliases}");
                    let file = std::fs::File::open("/proc/self/stat").unwrap();
                    context.transfer_fd(file.as_fd().try_clone_to_owned().unwrap())?;
                    Ok((Pid::this(), aliases))
                },
                &mut |state| {
                    assert_eq!(Pid::parent(), parent);
                    (state, ())
                },
            )
            .unwrap();
        let pid = actual_child.unwrap();
        assert_eq!(handle.cleanup().child_pid(), pid);
        let result = owned_complete(handle);
        assert_eq!(result.status(), ExitStatus::Exited(0));
        assert_eq!(result.decode().unwrap(), (pid, 0));
        assert_reaped(pid);
    }

    #[test]
    fn owned_parent_callback_unwind_reaps_child_and_retains_factory() {
        if crate::test_runs_in_own_process() {
            return;
        }
        struct FactoryCapture {
            shared: *mut SharedDropState,
            parent: Pid,
        }
        impl Drop for FactoryCapture {
            fn drop(&mut self) {
                assert!(
                    !unsafe { &*self.shared }
                        .finished
                        .swap(true, Ordering::SeqCst)
                );
                assert_eq!(Pid::this(), self.parent, "factory capture belongs to O");
            }
        }

        let (mapping, shared) = new_shared_drop_state();
        let capture = FactoryCapture {
            shared,
            parent: Pid::this(),
        };
        let actual_child = std::cell::Cell::new(None);
        let original_pidfd = std::cell::Cell::new(None);
        let observer_pidfd = std::cell::RefCell::new(None);
        let child_ref = &actual_child;
        let original_ref = &original_pidfd;
        let observer_ref = &observer_pidfd;
        let mut parent_start = move |context: ParentStartContext<'_>| -> Result<(), StartupError> {
            let _keep = &capture;
            child_ref.set(Some(context.child_pid()));
            original_ref.set(Some(context.child_pidfd().as_raw_fd()));
            // This duplicate observes actual exit; it never reaps or cancels C.
            *observer_ref.borrow_mut() = Some(context.child_pidfd().try_clone_to_owned().unwrap());
            panic!("owned startup parent panic");
        };
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Container::new().run_with_startup_owned(
                Duration::from_secs(2),
                &mut parent_start,
                &mut |_| Ok(()),
                &mut |()| {
                    unsafe { &*shared }.started.store(true, Ordering::Release);
                    ((), ())
                },
            )
        }));
        let panic = match caught {
            Err(panic) => panic,
            Ok(_) => panic!("the borrowed parent callback must unwind through the API"),
        };
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"owned startup parent panic")
        );
        let pid = actual_child
            .get()
            .expect("real child recorded before panic");
        let fd = original_pidfd.get().unwrap();
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(Errno::last(), Errno::EBADF, "library pidfd must be closed");
        let observer = observer_pidfd.borrow_mut().take().unwrap();
        let mut poll = libc::pollfd {
            fd: observer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 1);
        assert_ne!(poll.revents & (libc::POLLIN | libc::POLLHUP), 0);
        assert_eq!(poll.revents & libc::POLLNVAL, 0);
        assert_reaped(pid);
        assert!(!unsafe { &*shared }.started.load(Ordering::Acquire));
        assert!(!unsafe { &*shared }.finished.load(Ordering::Acquire));
        eprintln!(
            "owned parent unwind: child={pid} exit_events={} reaped=true library_pidfd_closed=true factory_retained=true workload_started=false",
            poll.revents
        );
        drop(parent_start);
        assert!(unsafe { &*shared }.finished.load(Ordering::Acquire));
        drop(observer);
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn owned_startup_namespace_and_filter_are_unchanged() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let result = Container::new()
            .unshare(Namespace::USER | Namespace::PID)
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| (namespace_population_probe(), ()),
            )
            .unwrap();
        assert_eq!(owned_complete(result).decode().unwrap(), (1, 2, 3));
        let filter = seccomp::FilterBuilder::new()
            .default_action(seccomp::Action::Allow)
            .syscalls([
                (
                    syscalls::Sysno::sendmsg,
                    seccomp::Action::Errno(Errno::EPERM),
                ),
                (
                    syscalls::Sysno::recvmsg,
                    seccomp::Action::Errno(Errno::EPERM),
                ),
                (
                    syscalls::Sysno::getppid,
                    seccomp::Action::Errno(Errno::EPERM),
                ),
            ])
            .build();
        let result = Container::new()
            .seccomp(filter)
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| {
                    (
                        Errno::result(unsafe { libc::syscall(libc::SYS_getppid) }),
                        (),
                    )
                },
            )
            .unwrap();
        assert_eq!(owned_complete(result).decode().unwrap(), Err(Errno::EPERM));
    }

    #[test]
    fn owned_startup_large_result_drains_before_pending_teardown() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let handle = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| (vec![37_u8; 10 * 1024 * 1024], BlockingDrop { shared }),
            )
            .unwrap();
        let bytes = handle.provisional_bytes().to_vec();
        let capacity = OWNED_RESULT_PIPE_CAPACITY
            .with(|capacity| capacity.get())
            .unwrap();
        assert!(capacity > 0);
        assert!(bytes.len() > capacity as usize);
        eprintln!(
            "owned result pipe capacity={capacity} encoded_bytes={}",
            bytes.len()
        );
        let pid = handle.cleanup().child_pid();
        let pending = match handle.finalize_until(Instant::now() + Duration::from_millis(20)) {
            OwnedFinalize::Pending(run) => run,
            other => panic!("blocked teardown unexpectedly {}", outcome_kind(&other)),
        };
        assert_eq!(pending.cleanup().child_pid(), pid);
        assert!(pending.result_eof());
        assert_eq!(pending.provisional_bytes(), bytes);
        unsafe { &*shared }.release.store(true, Ordering::Release);
        let result = match pending.retry_until(Instant::now() + Duration::from_secs(2)) {
            OwnedFinalize::Complete(result) => result,
            other => panic!("released child unexpectedly {}", outcome_kind(&other)),
        };
        assert_eq!(result.encoded_bytes(), bytes);
        assert_eq!(result.decode().unwrap(), vec![37_u8; 10 * 1024 * 1024]);
        assert_reaped(pid);
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    static OWNED_DECODE_COUNT: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    #[derive(Debug, serde::Serialize)]
    struct OwnedDecodeProbe(u32);
    impl<'de> serde::Deserialize<'de> for OwnedDecodeProbe {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            OWNED_DECODE_COUNT.fetch_add(1, Ordering::SeqCst);
            Ok(Self(<u32 as serde::Deserialize>::deserialize(
                deserializer,
            )?))
        }
    }

    #[test]
    fn owned_pending_result_never_constructs_generic_value() {
        if crate::test_runs_in_own_process() {
            return;
        }
        OWNED_DECODE_COUNT.store(0, Ordering::SeqCst);
        let (mapping, shared) = new_shared_drop_state();
        let handle = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| (OwnedDecodeProbe(91), BlockingDrop { shared }),
            )
            .unwrap();
        assert_eq!(OWNED_DECODE_COUNT.load(Ordering::SeqCst), 0);
        let pending = match handle.finalize_until(Instant::now()) {
            OwnedFinalize::Pending(run) => run,
            _ => panic!("child should still own deferred teardown"),
        };
        assert_eq!(OWNED_DECODE_COUNT.load(Ordering::SeqCst), 0);
        unsafe { &*shared }.release.store(true, Ordering::Release);
        let result = match pending.retry_until(Instant::now() + Duration::from_secs(2)) {
            OwnedFinalize::Complete(result) => result,
            _ => panic!("actual child should complete"),
        };
        assert_eq!(OWNED_DECODE_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(result.decode().unwrap().0, 91);
        assert_eq!(OWNED_DECODE_COUNT.load(Ordering::SeqCst), 1);
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn owned_lost_wait_status_is_physical_exit_not_success() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let handle = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| (42_u32, ()),
            )
            .unwrap();
        let pid = handle.cleanup().child_pid();
        let bytes = handle.provisional_bytes().to_vec();
        // Deliberate opposing violation of the exclusive-reaper contract.
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid.as_raw(), &mut status, 0) },
            pid.as_raw()
        );
        assert_eq!(ExitStatus::from_raw(status), ExitStatus::Exited(0));
        match handle.finalize_until(Instant::now() + Duration::from_secs(2)) {
            OwnedFinalize::Failed { cause, cleanup } => {
                assert_eq!(cause, OwnedRunFailure::WaitStatusUnavailable);
                assert_eq!(
                    cleanup.cleanup().observation(),
                    ChildCleanupObservation::ExitedWithoutWaitStatus
                );
                assert_eq!(cleanup.cleanup().last_error(), Some(Errno::ECHILD));
                assert_eq!(cleanup.provisional_bytes(), bytes);
                assert_reaped(pid);
            }
            _ => panic!("lost wait status must never qualify"),
        }
    }

    #[test]
    fn owned_startup_before_parent_failure_retains_cleanup_authority() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        OWNED_STARTUP_CANCEL_ERROR.with(|v| v.set(Some(Errno::EPERM)));
        let mut called = false;
        let failed = Container::new()
            .run_with_startup_owned(
                Duration::from_millis(50),
                &mut |_| {
                    called = true;
                    Ok(())
                },
                &mut |_| {
                    while !unsafe { &*shared }.release.load(Ordering::Acquire) {
                        unsafe { libc::sched_yield() };
                    }
                    Ok(())
                },
                &mut |()| ((), ()),
            )
            .unwrap_err();
        assert!(!called);
        match failed {
            StartupOwnedFailure::AfterClone { cause, run } => {
                assert_eq!(cause, OwnedRunFailure::Startup(StartupError::TimedOut));
                assert_eq!(run.cleanup().last_error(), Some(Errno::EPERM));
                assert_eq!(
                    run.cleanup().observation(),
                    ChildCleanupObservation::Pending
                );
                let pid = run.cleanup().child_pid();
                assert_eq!(unsafe { libc::kill(pid.as_raw(), 0) }, 0);
                let fd = run.cleanup().pidfd.as_ref().unwrap().as_raw_fd();
                match run.retry_until(Instant::now() + Duration::from_secs(2)) {
                    OwnedFinalize::Failed {
                        cause: again,
                        cleanup,
                    } => {
                        assert_eq!(cause, again);
                        assert_eq!(cleanup.cleanup().pidfd.as_ref().unwrap().as_raw_fd(), fd);
                        assert_eq!(
                            cleanup.cleanup().observation(),
                            ChildCleanupObservation::Reaped(ExitStatus::Signaled(
                                Signal::SIGKILL,
                                false
                            ))
                        );
                        assert_reaped(pid);
                    }
                    _ => panic!("cleanup must not erase first refusal"),
                }
            }
            _ => panic!("a real child was created"),
        }
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn owned_signal_esrch_is_not_a_terminal_status() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let mut handle = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| (7_u32, BlockingDrop { shared }),
            )
            .unwrap();
        let child = handle.inner.child.as_mut().unwrap();
        child.signal_error_once = Some(Errno::ESRCH);
        assert_eq!(
            child.cancel_and_wait_until(Instant::now() + Duration::from_millis(20)),
            ChildCleanupObservation::Pending
        );
        assert_eq!(child.last_error(), Some(Errno::ESRCH));
        unsafe { &*shared }.release.store(true, Ordering::Release);
        assert_eq!(owned_complete(handle).decode().unwrap(), 7);
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn owned_result_read_error_retains_same_fd_partial_bytes_and_child() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let (reader, writer) = pipe().unwrap();
        let reader_fd = reader.as_raw_fd();
        let writer_fd = writer.as_raw_fd();
        let mut stack = child_stack().unwrap();
        let child = super::super::clone::clone_with_stack_owned(
            || {
                unsafe { libc::close(reader_fd) };
                let mut out = Fd::new(writer_fd);
                out.write_all(b"abc").unwrap();
                unsafe { &*shared }.started.store(true, Ordering::Release);
                while !unsafe { &*shared }.release.load(Ordering::Acquire) {
                    unsafe { libc::sched_yield() };
                }
                0
            },
            Namespace::empty(),
            &mut stack,
        )
        .unwrap();
        drop(writer);
        let mut owned = OwnedFinalization::<u32>::new(OwnedContainerCleanup::new(child), reader);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !unsafe { &*shared }.started.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(unsafe { &*shared }.started.load(Ordering::Acquire));
        owned.reader.as_ref().unwrap().set_nonblocking().unwrap();
        let identity = std::fs::read_link(format!("/proc/self/fd/{reader_fd}")).unwrap();
        let cause = owned.drain().unwrap_err();
        assert_eq!(cause, OwnedRunFailure::ResultRead(Errno::EAGAIN));
        assert_eq!(owned.bytes, b"abc");
        owned.child.as_mut().unwrap().signal_error_once = Some(Errno::EPERM);
        let run = match owned.fail(cause, Instant::now()) {
            StartupOwnedFailure::AfterClone { run, .. } => run,
            _ => unreachable!(),
        };
        assert_eq!(run.reader.as_ref().unwrap().as_raw_fd(), reader_fd);
        assert_eq!(
            std::fs::read_link(format!("/proc/self/fd/{reader_fd}")).unwrap(),
            identity
        );
        assert_eq!(run.provisional_bytes(), b"abc");
        assert!(!run.result_eof());
        match run.retry_until(Instant::now() + Duration::from_secs(2)) {
            OwnedFinalize::Failed {
                cause: again,
                cleanup,
            } => {
                assert_eq!(again, cause);
                assert_eq!(cleanup.provisional_bytes(), b"abc");
                assert!(matches!(
                    cleanup.cleanup().observation(),
                    ChildCleanupObservation::Reaped(_)
                ));
                assert_eq!(cleanup.reader.as_ref().unwrap().as_raw_fd(), reader_fd);
                drop(cleanup);
            }
            _ => panic!("partial failed result cannot become successful"),
        }
        assert_eq!(unsafe { libc::fcntl(reader_fd, libc::F_GETFD) }, -1);
        assert_eq!(Errno::last(), Errno::EBADF);
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn owned_atomic_clone_refusals_do_not_start_work() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use super::super::clone::OwnedCloneTestFault;
        use super::super::clone::clone_with_stack_owned;
        let _fault = OwnedCloneFaultGuard::install(OwnedCloneTestFault::Probe(Errno::ENOSYS));
        let result = Container::new().run_with_startup_owned(
            Duration::from_secs(2),
            &mut |_| panic!("no parent callback"),
            &mut |_| -> Result<(), StartupError> { panic!("no child callback") },
            &mut |()| ((), ()),
        );
        assert!(matches!(
            result,
            Err(StartupOwnedFailure::BeforeClone {
                cause: StartupError::Io(Errno::ENOSYS)
            })
        ));
        drop(_fault);
        for flag in [
            libc::CLONE_VM,
            libc::CLONE_FILES,
            libc::CLONE_FS,
            libc::CLONE_SIGHAND,
            libc::CLONE_PARENT_SETTID,
            libc::CLONE_THREAD,
            libc::CLONE_VFORK,
            libc::CLONE_PARENT,
            libc::CLONE_DETACHED,
        ] {
            let mut stack = child_stack().unwrap();
            let result = clone_with_stack_owned(
                || panic!("invalid flags must not clone"),
                Namespace::from_bits_retain(flag),
                &mut stack,
            );
            assert!(matches!(result, Err(Errno::EINVAL)));
        }
        // RLIMIT is changed ONLY inside this actual child subprocess. The
        // shared libtest process and its threads retain their original limits.
        for atomic in [false, true] {
            let errno = Container::new()
                .run(|| {
                    if atomic {
                        let _fault =
                            OwnedCloneFaultGuard::install(OwnedCloneTestFault::ExhaustAtClone);
                        let mut stack = child_stack().unwrap();
                        clone_with_stack_owned(|| 0, Namespace::empty(), &mut stack)
                            .err()
                            .unwrap()
                    } else {
                        let limit = libc::rlimit {
                            rlim_cur: 0,
                            rlim_max: 0,
                        };
                        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
                        let mut stack = child_stack().unwrap();
                        clone_with_stack_owned(|| 0, Namespace::empty(), &mut stack)
                            .err()
                            .unwrap()
                    }
                })
                .unwrap();
            assert_eq!(errno, Errno::EMFILE);
        }
    }

    #[test]
    fn owned_missing_atomic_pidfd_refuses_permission_without_fake_owner() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let _fault =
            OwnedCloneFaultGuard::install(super::super::clone::OwnedCloneTestFault::MissingPidfd);
        let (mapping, shared) = new_shared_drop_state();
        let result = Container::new().run_with_startup_owned(
            Duration::from_millis(50),
            &mut |_| panic!("invalid atomic owner must not authorize parent setup"),
            &mut |_| Ok(()),
            &mut |()| {
                unsafe { &*shared }.started.store(true, Ordering::Release);
                ((), ())
            },
        );
        match result {
            Err(StartupOwnedFailure::AfterClone { cause, run }) => {
                assert_eq!(cause, OwnedRunFailure::Startup(StartupError::Protocol));
                assert!(run.cleanup().pidfd.is_none());
                let pid = run.cleanup().child_pid();
                drop(run);
                assert_reaped(pid);
            }
            _ => panic!("missing atomic output must refuse"),
        }
        assert!(!unsafe { &*shared }.started.load(Ordering::Acquire));
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    struct OwnedExitDrop(i32);
    impl Drop for OwnedExitDrop {
        fn drop(&mut self) {
            unsafe { libc::_exit(self.0) }
        }
    }
    struct OwnedSignalDrop;
    impl Drop for OwnedSignalDrop {
        fn drop(&mut self) {
            unsafe { libc::raise(libc::SIGPIPE) };
        }
    }

    #[test]
    fn owned_nonzero_and_signal_after_result_remain_failures() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let run = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| (123_u32, OwnedExitDrop(73)),
            )
            .unwrap();
        match run.finalize_until(Instant::now() + Duration::from_secs(2)) {
            OwnedFinalize::Failed { cause, cleanup } => {
                assert_eq!(cause, OwnedRunFailure::ChildStatus(ExitStatus::Exited(73)));
                assert!(!cleanup.provisional_bytes().is_empty());
            }
            _ => panic!("nonzero cleanup cannot yield the provisional result"),
        }
        let run = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| (123_u32, OwnedSignalDrop),
            )
            .unwrap();
        match run.finalize_until(Instant::now() + Duration::from_secs(2)) {
            OwnedFinalize::Failed { cause, .. } => assert_eq!(
                cause,
                OwnedRunFailure::ChildStatus(ExitStatus::Signaled(Signal::SIGPIPE, false))
            ),
            _ => panic!("SIGPIPE cannot become serde error or exit zero"),
        }
    }

    #[test]
    fn owned_closed_result_reader_observes_actual_sigpipe() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (reader, writer) = pipe().unwrap();
        let rfd = reader.as_raw_fd();
        let wfd = writer.as_raw_fd();
        let (mapping, shared) = new_shared_drop_state();
        let mut stack = child_stack().unwrap();
        let child = super::super::clone::clone_with_stack_owned(
            || {
                unsafe { libc::close(rfd) };
                unsafe { reset_signal_handling() }.unwrap();
                while !unsafe { &*shared }.release.load(Ordering::Acquire) {
                    unsafe { libc::sched_yield() };
                }
                Fd::new(wfd)
                    .write_all(b"ordinary serialized output")
                    .unwrap();
                0
            },
            Namespace::empty(),
            &mut stack,
        )
        .unwrap();
        let mut owner = OwnedContainerCleanup::new(child);
        drop(reader);
        drop(writer);
        unsafe { &*shared }.release.store(true, Ordering::Release);
        assert_eq!(
            owner.wait_until(Instant::now() + Duration::from_secs(2)),
            ChildCleanupObservation::Reaped(ExitStatus::Signaled(Signal::SIGPIPE, false))
        );
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn owned_invalid_request_and_permission_never_enter_work() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use StartupTestFault::*;
        for fault in [
            RequestEmptyTrailing,
            RequestDuplicate,
            RequestMalformed,
            RequestTrailingRights,
            PermissionEmptyTrailing,
            PermissionDuplicate,
            PermissionMalformed,
            PermissionTrailingRights,
        ] {
            let _fault = StartupFaultGuard::install(fault);
            let (mapping, shared) = new_shared_drop_state();
            let result = Container::new().run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| {
                    unsafe { &*shared }.started.store(true, Ordering::Release);
                    ((), ())
                },
            );
            match result {
                Err(StartupOwnedFailure::AfterClone { run, .. }) => drop(run),
                Ok(run) => match run.finalize_until(Instant::now() + Duration::from_secs(2)) {
                    OwnedFinalize::Complete(_) => panic!("corrupt permission cannot complete"),
                    OwnedFinalize::Failed { .. } => (),
                    OwnedFinalize::Pending(_) => panic!("corrupt child did not settle"),
                },
                _ => panic!("real child must exist"),
            }
            assert!(!unsafe { &*shared }.started.load(Ordering::Acquire));
            unsafe { unmap_shared_drop_state(mapping, shared) };
        }
    }

    #[test]
    fn owned_persistent_signal_refusal_still_observes_independent_exit() {
        if crate::test_runs_in_own_process() {
            return;
        }
        // Install the real policy ONLY in this isolated process. Both inner
        // cancellation attempts must see EPERM; actual wait still obtains 17.
        let filter = seccomp::FilterBuilder::new()
            .default_action(seccomp::Action::Allow)
            .syscalls([(
                syscalls::Sysno::pidfd_send_signal,
                seccomp::Action::Errno(Errno::EPERM),
            )])
            .build();
        let observed = Container::new()
            .seccomp(filter)
            .run(|| {
                let (mapping, shared) = new_shared_drop_state();
                let mut stack = child_stack().unwrap();
                let child = super::super::clone::clone_with_stack_owned(
                    || {
                        while !unsafe { &*shared }.release.load(Ordering::Acquire) {
                            unsafe { libc::sched_yield() };
                        }
                        17
                    },
                    Namespace::empty(),
                    &mut stack,
                )
                .unwrap();
                let pid = child.pid;
                let mut owner = OwnedContainerCleanup::new(child);
                let fd = owner.pidfd.as_ref().unwrap().as_raw_fd();
                assert_ne!(
                    unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                    0
                );
                assert_eq!(
                    owner.cancel_and_wait_until(Instant::now() + Duration::from_millis(20)),
                    ChildCleanupObservation::Pending
                );
                assert_eq!(owner.last_error(), Some(Errno::EPERM));
                unsafe { &*shared }.release.store(true, Ordering::Release);
                assert_eq!(
                    owner.cancel_and_wait_until(Instant::now() + Duration::from_secs(2)),
                    ChildCleanupObservation::Reaped(ExitStatus::Exited(17))
                );
                assert_eq!(owner.last_error(), Some(Errno::EPERM));
                assert_eq!(owner.child_pid(), pid);
                assert_reaped(pid);
                drop(owner);
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                assert_eq!(Errno::last(), Errno::EBADF);
                unsafe { unmap_shared_drop_state(mapping, shared) };
                (17, Errno::EPERM)
            })
            .unwrap();
        assert_eq!(observed, (17, Errno::EPERM));
    }

    #[test]
    fn owned_atomic_immediate_exit_has_actual_status_and_reclaims_fd() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mut stack = child_stack().unwrap();
        let child =
            super::super::clone::clone_with_stack_owned(|| 17, Namespace::empty(), &mut stack)
                .unwrap();
        let pid = child.pid;
        let mut owner = OwnedContainerCleanup::new(child);
        let fd = owner.pidfd.as_ref().unwrap().as_raw_fd();
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert_eq!(
            owner.wait_until(Instant::now() + Duration::from_secs(2)),
            ChildCleanupObservation::Reaped(ExitStatus::Exited(17))
        );
        assert_reaped(pid);
        drop(owner);
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(Errno::last(), Errno::EBADF);
    }

    #[test]
    fn owned_wait_retries_actual_interrupted_pidfd_poll() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let _serial = WAITPID_SIGNAL_TEST.lock().unwrap();
        OWNED_POLL_INTERRUPTED.store(0, Ordering::Release);
        let previous = unsafe {
            sigaction(
                Signal::SIGUSR2,
                &SigAction::new(
                    SigHandler::Handler(ignore_test_signal),
                    SaFlags::empty(),
                    SigSet::empty(),
                ),
            )
        }
        .unwrap();
        let (mapping, shared) = new_shared_drop_state();
        let run = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| (52_u32, BlockingDrop { shared }),
            )
            .unwrap();
        let pid = run.cleanup().child_pid();
        let waiting_thread = unsafe { libc::pthread_self() };
        let shared_address = shared as usize;
        // The O helper is created only after clone; no worker is inherited.
        let interrupter = std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(2);
            while OWNED_POLL_INTERRUPTED.load(Ordering::Acquire) == 0 && Instant::now() < until {
                assert_eq!(
                    unsafe { libc::pthread_kill(waiting_thread, libc::SIGUSR2) },
                    0
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            unsafe { &*(shared_address as *mut SharedDropState) }
                .release
                .store(true, Ordering::Release);
        });
        let result = owned_complete(run);
        interrupter.join().unwrap();
        unsafe { sigaction(Signal::SIGUSR2, &previous) }.unwrap();
        assert!(OWNED_POLL_INTERRUPTED.load(Ordering::Acquire) > 0);
        assert_eq!(result.decode().unwrap(), 52);
        assert_reaped(pid);
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    struct OwnedFactoryDrop {
        index: usize,
        counters: *mut [std::sync::atomic::AtomicUsize; 8],
        parent: Pid,
    }
    impl Drop for OwnedFactoryDrop {
        fn drop(&mut self) {
            assert_eq!(
                Pid::this(),
                self.parent,
                "borrowed O factories must not be dropped in C"
            );
            let counters = unsafe { &*self.counters };
            assert_eq!(
                counters[3].load(Ordering::Acquire),
                1,
                "O worker must already be joined"
            );
            counters[self.index].fetch_add(1, Ordering::SeqCst);
        }
    }
    #[derive(Debug)]
    struct OwnedLifecycleValue(*mut [std::sync::atomic::AtomicUsize; 8]);
    impl serde::Serialize for OwnedLifecycleValue {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            (unsafe { &*self.0 })[0].fetch_add(1, Ordering::SeqCst);
            serializer.serialize_u32(29)
        }
    }
    impl Drop for OwnedLifecycleValue {
        fn drop(&mut self) {
            (unsafe { &*self.0 })[2].fetch_add(1, Ordering::SeqCst);
        }
    }
    struct OwnedLifecycleDeferred {
        shared: *mut SharedDropState,
        counters: *mut [std::sync::atomic::AtomicUsize; 8],
    }
    impl Drop for OwnedLifecycleDeferred {
        fn drop(&mut self) {
            drop(BlockingDrop {
                shared: self.shared,
            });
            (unsafe { &*self.counters })[1].fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn owned_borrowed_factories_remain_in_parent_until_child_and_worker_settle() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use std::sync::atomic::AtomicUsize;
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<[AtomicUsize; 8]>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let counters = mapping.cast::<[AtomicUsize; 8]>();
        unsafe { counters.write(std::array::from_fn(|_| AtomicUsize::new(0))) };
        let state = unsafe { &*counters };
        let (child_mapping, shared) = new_shared_drop_state();
        let worker_release = std::sync::Arc::new(AtomicBool::new(false));
        let worker = std::cell::RefCell::new(None);
        let parent_guard = OwnedFactoryDrop {
            index: 4,
            counters,
            parent: Pid::this(),
        };
        let child_guard = OwnedFactoryDrop {
            index: 5,
            counters,
            parent: Pid::this(),
        };
        let run_guard = OwnedFactoryDrop {
            index: 6,
            counters,
            parent: Pid::this(),
        };
        let worker_ref = &worker;
        let release_ref = &worker_release;
        let mut parent_start = move |_: ParentStartContext<'_>| {
            let _keep = &parent_guard;
            let release = std::sync::Arc::clone(release_ref);
            *worker_ref.borrow_mut() = Some(std::thread::spawn(move || {
                while !release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            }));
            Ok(())
        };
        let mut child_start = move |_: &mut ChildStartContext| {
            let _keep = &child_guard;
            Ok(())
        };
        let mut run = move |()| {
            let _keep = &run_guard;
            (
                OwnedLifecycleValue(counters),
                OwnedLifecycleDeferred { shared, counters },
            )
        };
        let handle = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut parent_start,
                &mut child_start,
                &mut run,
            )
            .unwrap();
        let pending = match handle.finalize_until(Instant::now()) {
            OwnedFinalize::Pending(pending) => pending,
            _ => panic!("C is still in user teardown"),
        };
        assert_eq!(state[0].load(Ordering::Acquire), 1);
        for counter in &state[1..] {
            assert_eq!(counter.load(Ordering::Acquire), 0);
        }
        unsafe { &*shared }.release.store(true, Ordering::Release);
        let result = match pending.retry_until(Instant::now() + Duration::from_secs(2)) {
            OwnedFinalize::Complete(result) => result,
            _ => panic!("original child should settle"),
        };
        assert_eq!(state[1].load(Ordering::Acquire), 1);
        assert_eq!(state[2].load(Ordering::Acquire), 1);
        for counter in &state[3..] {
            assert_eq!(counter.load(Ordering::Acquire), 0);
        }
        worker_release.store(true, Ordering::Release);
        worker.borrow_mut().take().unwrap().join().unwrap();
        state[3].store(1, Ordering::Release);
        drop(parent_start);
        drop(child_start);
        drop(run);
        for counter in &state[..7] {
            assert_eq!(counter.load(Ordering::Acquire), 1);
        }
        assert_eq!(state[7].load(Ordering::Acquire), 0);
        // The result remains encoded throughout C/O settlement; a different
        // decoding type here verifies the stable u32 wire, not user construction.
        assert_eq!(
            bincode::serde::decode_from_slice::<Result<u32, StartupError>, _>(
                result.encoded_bytes(),
                bincode::config::legacy()
            )
            .unwrap(),
            (Ok(29), result.encoded_bytes().len())
        );
        unsafe { unmap_shared_drop_state(child_mapping, shared) };
        unsafe {
            std::ptr::drop_in_place(counters);
            assert_eq!(
                libc::munmap(mapping, std::mem::size_of::<[AtomicUsize; 8]>()),
                0
            );
        }
    }

    #[test]
    fn owned_decode_refusal_retains_exact_bytes_and_actual_status() {
        if crate::test_runs_in_own_process() {
            return;
        }
        for bytes in [
            vec![255],
            {
                let mut bytes = bincode::serde::encode_to_vec(
                    Ok::<u32, StartupError>(19),
                    bincode::config::legacy(),
                )
                .unwrap();
                bytes.push(88);
                bytes
            },
            bincode::serde::encode_to_vec(
                Err::<u32, StartupError>(StartupError::Protocol),
                bincode::config::legacy(),
            )
            .unwrap(),
        ] {
            let run = Container::new()
                .run_with_startup_owned(
                    Duration::from_secs(2),
                    &mut |_| Ok(()),
                    &mut |_| Ok(()),
                    &mut |()| (19_u32, ()),
                )
                .unwrap();
            let mut result = owned_complete(run);
            // Deliberately corrupt only the held wire after genuine C settlement.
            result.bytes = bytes.clone();
            let failure = result.decode().unwrap_err();
            assert_eq!(failure.encoded_bytes(), bytes);
            assert_eq!(failure.status(), ExitStatus::Exited(0));
            assert_eq!(
                failure.cause(),
                OwnedRunFailure::Startup(StartupError::Protocol)
            );
        }
    }

    #[test]
    fn owned_unknown_wait_retains_payload_and_same_child_on_retry() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let mut run = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| (93_u32, BlockingDrop { shared }),
            )
            .unwrap();
        let bytes = run.provisional_bytes().to_vec();
        let pid = run.cleanup().child_pid();
        let fd = run.cleanup().pidfd.as_ref().unwrap().as_raw_fd();
        // Inject only the wait syscall error: the real child remains alive,
        // its real pidfd remains owned, and the retry performs real cancellation.
        run.inner.child.as_mut().unwrap().wait_error_once = Some(Errno::EIO);
        let cleanup = match run.finalize_until(Instant::now()) {
            OwnedFinalize::Failed { cause, cleanup } => {
                assert_eq!(cause, OwnedRunFailure::Cleanup(Errno::EIO));
                assert_eq!(
                    cleanup.cleanup().observation(),
                    ChildCleanupObservation::Unknown
                );
                assert_eq!(cleanup.provisional_bytes(), bytes);
                assert_eq!(cleanup.cleanup().pidfd.as_ref().unwrap().as_raw_fd(), fd);
                assert_eq!(cleanup.cleanup().child_pid(), pid);
                cleanup
            }
            _ => panic!("unknown wait must retain a failed owner"),
        };
        match cleanup.retry_until(Instant::now() + Duration::from_secs(2)) {
            OwnedFinalize::Failed { cause, cleanup } => {
                assert_eq!(cause, OwnedRunFailure::Cleanup(Errno::EIO));
                assert_eq!(cleanup.provisional_bytes(), bytes);
                assert_eq!(cleanup.cleanup().child_pid(), pid);
                assert_eq!(cleanup.cleanup().pidfd.as_ref().unwrap().as_raw_fd(), fd);
                assert_eq!(
                    cleanup.cleanup().observation(),
                    ChildCleanupObservation::Reaped(ExitStatus::Signaled(Signal::SIGKILL, false))
                );
                assert_reaped(pid);
            }
            _ => panic!("settlement must not erase original wait failure"),
        }
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    struct OwnedExternalFactory {
        parent: Pid,
        joined: std::sync::Arc<AtomicBool>,
        drops: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Drop for OwnedExternalFactory {
        fn drop(&mut self) {
            assert_eq!(Pid::this(), self.parent);
            assert!(
                self.joined.load(Ordering::Acquire),
                "factory dropped before O worker joined"
            );
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[derive(Debug)]
    struct OwnedSerializeExit;
    impl serde::Serialize for OwnedSerializeExit {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            // Die during serialization, before the buffered result can flush.
            unsafe { libc::_exit(73) }
        }
    }

    #[test]
    fn owned_post_ready_serialization_death_keeps_external_worker_and_factory() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use std::sync::Arc;
        let release = Arc::new(AtomicBool::new(false));
        let joined = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let factory = OwnedExternalFactory {
            parent: Pid::this(),
            joined: joined.clone(),
            drops: drops.clone(),
        };
        let worker = std::cell::RefCell::new(None);
        let worker_ref = &worker;
        let release_ref = &release;
        let mut parent_called = false;
        let called_ref = &mut parent_called;
        let mut parent = move |_: ParentStartContext<'_>| {
            let _keep = &factory;
            *called_ref = true;
            let release = Arc::clone(release_ref);
            *worker_ref.borrow_mut() = Some(std::thread::spawn(move || {
                while !release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            }));
            Ok(())
        };
        let failure = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut parent,
                &mut |_| Ok(()),
                &mut |()| (OwnedSerializeExit, ()),
            )
            .unwrap_err();
        match failure {
            StartupOwnedFailure::AfterClone { cause, run } => {
                assert_eq!(cause, OwnedRunFailure::Startup(StartupError::MissingResult));
                assert_eq!(
                    run.cleanup().observation(),
                    ChildCleanupObservation::Reaped(ExitStatus::Exited(73))
                );
                assert!(run.provisional_bytes().is_empty());
                assert_eq!(drops.load(Ordering::Acquire), 0);
                assert!(!joined.load(Ordering::Acquire));
                assert!(!worker.borrow().as_ref().unwrap().is_finished());
                let pid = run.cleanup().child_pid();
                drop(run);
                assert_reaped(pid);
            }
            _ => panic!("post-ready child death must retain actual cleanup"),
        }
        assert_eq!(drops.load(Ordering::Acquire), 0);
        release.store(true, Ordering::Release);
        worker.borrow_mut().take().unwrap().join().unwrap();
        joined.store(true, Ordering::Release);
        drop(parent);
        assert!(parent_called);
        assert_eq!(drops.load(Ordering::Acquire), 1);
    }

    #[test]
    fn owned_implicit_disposal_waits_before_worker_factory_and_second_clone() {
        if crate::test_runs_in_own_process() {
            return;
        }
        // Persistent cancellation refusal forces Drop to observe natural exit.
        // The policy and all helper threads live only in this isolated process.
        let filter = seccomp::FilterBuilder::new()
            .default_action(seccomp::Action::Allow)
            .syscalls([(
                syscalls::Sysno::pidfd_send_signal,
                seccomp::Action::Errno(Errno::EPERM),
            )])
            .build();
        let result = Container::new()
            .seccomp(filter)
            .run(|| {
                use std::sync::Arc;
                let (mapping, shared) = new_shared_drop_state();
                let release = Arc::new(AtomicBool::new(false));
                let joined = Arc::new(AtomicBool::new(false));
                let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let cancel_observed = Arc::new(AtomicBool::new(false));
                let second_clone = Arc::new(AtomicBool::new(false));
                let worker = std::cell::RefCell::new(None);
                let worker_ref = &worker;
                let release_ref = &release;
                let factory = OwnedExternalFactory {
                    parent: Pid::this(),
                    joined: joined.clone(),
                    drops: drops.clone(),
                };
                let mut parent = move |_: ParentStartContext<'_>| {
                    let _keep = &factory;
                    let release = Arc::clone(release_ref);
                    *worker_ref.borrow_mut() = Some(std::thread::spawn(move || {
                        while !release.load(Ordering::Acquire) {
                            std::thread::yield_now();
                        }
                    }));
                    Ok(())
                };
                let run = Container::new()
                    .run_with_startup_owned(
                        Duration::from_secs(2),
                        &mut parent,
                        &mut |_| Ok(()),
                        &mut |()| (41_u32, BlockingDrop { shared }),
                    )
                    .unwrap();
                let pid = run.cleanup().child_pid();
                let mut pending = match run.finalize_until(Instant::now()) {
                    OwnedFinalize::Pending(pending) => pending,
                    _ => panic!("child must still hold its teardown gate"),
                };
                pending.child.as_mut().unwrap().cancellation_observed =
                    Some(cancel_observed.clone());
                let shared_address = shared as usize;
                let observed = cancel_observed.clone();
                let observer_joined = joined.clone();
                let observer_drops = drops.clone();
                let observer_second = second_clone.clone();
                let controller = std::thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while !observed.load(Ordering::Acquire) && Instant::now() < deadline {
                        std::thread::yield_now();
                    }
                    assert!(
                        observed.load(Ordering::Acquire),
                        "actual cancellation was not attempted"
                    );
                    assert!(!observer_joined.load(Ordering::Acquire));
                    assert_eq!(observer_drops.load(Ordering::Acquire), 0);
                    assert!(!observer_second.load(Ordering::Acquire));
                    unsafe { &*(shared_address as *mut SharedDropState) }
                        .release
                        .store(true, Ordering::Release);
                });
                drop(pending); // implicit disposal retains ownership across EPERM
                assert_reaped(pid);
                assert!(unsafe { &*shared }.finished.load(Ordering::Acquire));
                controller.join().unwrap();
                assert_eq!(drops.load(Ordering::Acquire), 0);
                assert!(!joined.load(Ordering::Acquire));
                release.store(true, Ordering::Release);
                worker.borrow_mut().take().unwrap().join().unwrap();
                joined.store(true, Ordering::Release);
                drop(parent);
                assert_eq!(drops.load(Ordering::Acquire), 1);
                // This native caller's ordering is explicit; the API does not
                // certify arbitrary outside threads or supply an A3 clone token.
                second_clone.store(true, Ordering::Release);
                assert_eq!(Container::new().run(|| 23), Ok(23));
                unsafe { unmap_shared_drop_state(mapping, shared) };
                23
            })
            .unwrap();
        assert_eq!(result, 23);
    }

    #[derive(Debug)]
    struct OwnedStalledSerializer(*mut SharedDropState);
    impl serde::Serialize for OwnedStalledSerializer {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            unsafe { &*self.0 }.started.store(true, Ordering::Release);
            loop {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    #[test]
    fn owned_stalled_serializer_requires_outer_process_containment() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let mut stack = child_stack().unwrap();
        // The supervised outer process is PID-namespace init. Its forced death
        // also terminates the intentionally stuck inner serializer; no orphan
        // helper is left behind. This is a native control, not a guest run.
        let outer = super::super::clone::clone_with_stack_owned(
            || {
                assert_eq!(Pid::this().as_raw(), 1);
                let _never_returns = Container::new().run_with_startup_owned(
                    Duration::from_millis(50),
                    &mut |_| Ok(()),
                    &mut |_| Ok(()),
                    &mut |()| (OwnedStalledSerializer(shared), ()),
                );
                unsafe { &*shared }.finished.store(true, Ordering::Release);
                99
            },
            Namespace::USER | Namespace::PID,
            &mut stack,
        )
        .unwrap();
        let mut outer = OwnedContainerCleanup::new(outer);
        let pid = outer.child_pid();
        let ready_deadline = Instant::now() + Duration::from_secs(2);
        while !unsafe { &*shared }.started.load(Ordering::Acquire)
            && Instant::now() < ready_deadline
        {
            std::thread::yield_now();
        }
        assert!(unsafe { &*shared }.started.load(Ordering::Acquire));
        // Exceeds the expired startup deadline, which is NOT a result budget.
        assert_eq!(
            outer.wait_until(Instant::now() + Duration::from_millis(100)),
            ChildCleanupObservation::Pending
        );
        assert!(!unsafe { &*shared }.finished.load(Ordering::Acquire));
        assert_eq!(
            outer.cancel_and_wait_until(Instant::now() + Duration::from_secs(2)),
            ChildCleanupObservation::Reaped(ExitStatus::Signaled(Signal::SIGKILL, false))
        );
        assert_reaped(pid);
        eprintln!(
            "stalled serializer: outer_pid={pid} actual_exit=SIGKILL after actual Pending; library result acquisition did not return"
        );
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn owned_provisional_cancel_reaps_actual_child_and_preserves_bytes() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let run = Container::new()
            .run_with_startup_owned(
                Duration::from_secs(2),
                &mut |_| Ok(()),
                &mut |_| Ok(()),
                &mut |()| (77_u32, BlockingDrop { shared }),
            )
            .unwrap();
        let pid = run.cleanup().child_pid();
        let fd = run.cleanup().pidfd.as_ref().unwrap().as_raw_fd();
        let bytes = run.provisional_bytes().to_vec();
        let failed = match run.cancel_until(Instant::now() + Duration::from_secs(2)) {
            OwnedFinalize::Failed { cause, cleanup } => {
                assert_eq!(cause, OwnedRunFailure::Cancelled);
                assert_eq!(
                    cleanup.cleanup().observation(),
                    ChildCleanupObservation::Reaped(ExitStatus::Signaled(Signal::SIGKILL, false))
                );
                assert_eq!(cleanup.cleanup().child_pid(), pid);
                assert_eq!(cleanup.cleanup().pidfd.as_ref().unwrap().as_raw_fd(), fd);
                assert_eq!(cleanup.provisional_bytes(), bytes);
                assert!(cleanup.result_eof());
                cleanup
            }
            _ => panic!("explicit cancellation must remain failed"),
        };
        assert_reaped(pid);
        match failed.retry_until(Instant::now()) {
            OwnedFinalize::Failed { cause, cleanup } => {
                assert_eq!(cause, OwnedRunFailure::Cancelled);
                assert_eq!(cleanup.provisional_bytes(), bytes);
            }
            _ => panic!("cleanup must not erase cancellation"),
        }
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn owned_pending_cancel_stays_failed_after_refused_signal_and_exit_zero() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let filter = seccomp::FilterBuilder::new()
            .default_action(seccomp::Action::Allow)
            .syscalls([(
                syscalls::Sysno::pidfd_send_signal,
                seccomp::Action::Errno(Errno::EPERM),
            )])
            .build();
        let result = Container::new()
            .seccomp(filter)
            .run(|| {
                let (mapping, shared) = new_shared_drop_state();
                let run = Container::new()
                    .run_with_startup_owned(
                        Duration::from_secs(2),
                        &mut |_| Ok(()),
                        &mut |_| Ok(()),
                        &mut |()| (78_u32, BlockingDrop { shared }),
                    )
                    .unwrap();
                let pid = run.cleanup().child_pid();
                let fd = run.cleanup().pidfd.as_ref().unwrap().as_raw_fd();
                let bytes = run.provisional_bytes().to_vec();
                let pending = match run.finalize_until(Instant::now()) {
                    OwnedFinalize::Pending(pending) => pending,
                    _ => panic!("real child must remain held after result EOF"),
                };
                let failed = match pending.cancel_until(Instant::now() + Duration::from_millis(20))
                {
                    OwnedFinalize::Failed { cause, cleanup } => {
                        assert_eq!(cause, OwnedRunFailure::Cancelled);
                        assert_eq!(
                            cleanup.cleanup().observation(),
                            ChildCleanupObservation::Pending
                        );
                        assert_eq!(cleanup.cleanup().last_error(), Some(Errno::EPERM));
                        assert_eq!(cleanup.cleanup().child_pid(), pid);
                        assert_eq!(cleanup.cleanup().pidfd.as_ref().unwrap().as_raw_fd(), fd);
                        assert_eq!(cleanup.provisional_bytes(), bytes);
                        cleanup
                    }
                    _ => panic!("failed bounded cancellation must retain the pending owner"),
                };
                unsafe { &*shared }.release.store(true, Ordering::Release);
                match failed.retry_until(Instant::now() + Duration::from_secs(2)) {
                    OwnedFinalize::Failed { cause, cleanup } => {
                        assert_eq!(cause, OwnedRunFailure::Cancelled);
                        assert_eq!(
                            cleanup.cleanup().observation(),
                            ChildCleanupObservation::Reaped(ExitStatus::Exited(0))
                        );
                        assert_eq!(cleanup.cleanup().last_error(), Some(Errno::EPERM));
                        assert_eq!(cleanup.cleanup().child_pid(), pid);
                        assert_eq!(cleanup.cleanup().pidfd.as_ref().unwrap().as_raw_fd(), fd);
                        assert_eq!(cleanup.provisional_bytes(), bytes);
                    }
                    _ => panic!("real exit zero cannot promote a cancelled run"),
                }
                assert_reaped(pid);
                unsafe { unmap_shared_drop_state(mapping, shared) };
                true
            })
            .unwrap();
        assert!(result);
    }

    struct StartupFaultGuard;

    impl StartupFaultGuard {
        fn install(fault: StartupTestFault) -> Self {
            STARTUP_TEST_FAULT.with(|value| {
                assert!(value.get() == StartupTestFault::None);
                value.set(fault);
            });
            Self
        }
    }

    impl Drop for StartupFaultGuard {
        fn drop(&mut self) {
            STARTUP_TEST_FAULT.with(|value| value.set(StartupTestFault::None));
        }
    }

    #[test]
    fn startup_corrupt_request_or_permission_never_runs_workload() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use StartupTestFault::*;
        for fault in [
            RequestEmptyTrailing,
            RequestDuplicate,
            RequestMalformed,
            RequestTrailingRights,
            PermissionEmptyTrailing,
            PermissionDuplicate,
            PermissionMalformed,
            PermissionTrailingRights,
        ] {
            let _fault = StartupFaultGuard::install(fault);
            let (mapping, shared) = new_shared_drop_state();
            let mut parent_called = false;
            let result = Container::new().run_with_startup(
                Duration::from_secs(2),
                |_| {
                    parent_called = true;
                    Ok(())
                },
                |_| Ok(()),
                |()| {
                    unsafe { &*shared }.started.store(true, Ordering::Release);
                    ((), ())
                },
            );
            assert!(matches!(
                result,
                Err(StartupRunError::Child {
                    cause: StartupError::Protocol,
                    ..
                })
            ));
            assert_eq!(
                parent_called,
                matches!(
                    fault,
                    PermissionEmptyTrailing
                        | PermissionDuplicate
                        | PermissionMalformed
                        | PermissionTrailingRights
                )
            );
            assert!(!unsafe { &*shared }.started.load(Ordering::Acquire));
            unsafe { unmap_shared_drop_state(mapping, shared) };
        }
    }

    #[test]
    fn startup_fragmented_request_transfers_each_right_exactly_once() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let _fault = StartupFaultGuard::install(StartupTestFault::Fragmented);
        let (pid, handle) = Container::new()
            .run_with_startup(
                Duration::from_secs(2),
                |mut context| {
                    assert_eq!(context.descriptor_count(), MAX_STARTUP_FDS);
                    for index in 0..MAX_STARTUP_FDS {
                        assert!(context.take_fd(index).is_some());
                    }
                    Ok(context.child_pid())
                },
                |context| {
                    for _ in 0..MAX_STARTUP_FDS {
                        context.transfer_fd(std::fs::File::open("/dev/null").unwrap().into())?;
                    }
                    Ok(())
                },
                |()| (42, ()),
            )
            .unwrap();
        assert_eq!(
            handle.finalize_with_status(),
            Ok((42, ExitStatus::Exited(0)))
        );
        assert_reaped(pid);
    }

    #[test]
    fn startup_final_permission_has_no_later_parent_deadline_validation() {
        if crate::test_runs_in_own_process() {
            return;
        }
        // Deliberately delay the parent after final permission is sent and its
        // write side closed. This models scheduling after release, without
        // bypassing any protocol checks. The child's genuine result still must
        // be drained and its actual terminal status checked.
        let _fault = StartupFaultGuard::install(StartupTestFault::ObservePermissionLate);
        let (pid, handle) = Container::new()
            .run_with_startup(
                Duration::from_millis(100),
                |context| Ok(context.child_pid()),
                |_| Ok(()),
                |()| (42, ()),
            )
            .unwrap();
        assert_eq!(
            handle.finalize_with_status(),
            Ok((42, ExitStatus::Exited(0)))
        );
        assert_reaped(pid);
    }

    #[test]
    fn startup_ignored_descriptor_overflow_still_refuses_workload() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let result = Container::new().run_with_startup(
            Duration::from_secs(2),
            |_| Ok(()),
            |context| {
                for _ in 0..=MAX_STARTUP_FDS {
                    let _ = context.transfer_fd(std::fs::File::open("/dev/null").unwrap().into());
                }
                Ok(())
            },
            |()| {
                unsafe { &*shared }.started.store(true, Ordering::Release);
                ((), ())
            },
        );
        assert!(matches!(
            result,
            Err(StartupRunError::Child {
                cause: StartupError::Protocol,
                ..
            })
        ));
        assert!(!unsafe { &*shared }.started.load(Ordering::Acquire));
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    fn assert_reaped(pid: Pid) {
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid.as_raw(), &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(Errno::last(), Errno::ECHILD);
    }

    #[test]
    fn startup_binds_parent_child_and_transfers_owned_descriptor_once() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use std::os::fd::AsFd;
        let parent = Pid::this();
        let (mapping, shared) = new_shared_drop_state();
        let (owner, handle) = Container::new()
            .run_with_startup(
                Duration::from_secs(2),
                |mut context| {
                    assert_eq!(Pid::this(), parent);
                    assert_ne!(context.child_pid(), parent);
                    assert!(context.child_pidfd().as_raw_fd() >= 0);
                    assert_eq!(context.descriptor_count(), 1);
                    let fd = context.take_fd(0).unwrap();
                    assert!(context.take_fd(0).is_none());
                    assert!(context.take_fd(MAX_STARTUP_FDS).is_none());
                    assert_ne!(
                        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                        0
                    );
                    let mut file = std::fs::File::from(fd);
                    let mut contents = String::new();
                    file.read_to_string(&mut contents).unwrap();
                    assert!(contents.starts_with(&format!("{} ", context.child_pid())));
                    unsafe { &*shared }.release.store(true, Ordering::Release);
                    Ok(context.child_pid())
                },
                |context| {
                    let file = std::fs::File::open("/proc/self/stat").unwrap();
                    context.transfer_fd(file.as_fd().try_clone_to_owned().unwrap())?;
                    Ok(Pid::this())
                },
                |pid| {
                    assert!(unsafe { &*shared }.release.load(Ordering::Acquire));
                    assert_eq!(pid, Pid::this());
                    assert_eq!(Pid::parent(), parent);
                    (pid, ())
                },
            )
            .unwrap();
        assert_eq!(
            handle.finalize_with_status(),
            Ok((owner, ExitStatus::Exited(0)))
        );
        assert_reaped(owner);
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    fn namespace_population_probe() -> (i32, i32, i32) {
        let root = Pid::this().as_raw();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::_exit(0) }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(ExitStatus::from_raw(status), ExitStatus::Exited(0));
        let thread = std::thread::spawn(|| unsafe { libc::syscall(libc::SYS_gettid) as i32 })
            .join()
            .unwrap();
        (root, child, thread)
    }

    #[test]
    fn startup_does_not_allocate_a_child_namespace_helper_pid() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let baseline = Container::new()
            .unshare(Namespace::USER | Namespace::PID)
            .run(namespace_population_probe)
            .unwrap();
        assert_eq!(baseline, (1, 2, 3));
        let parent = Pid::this();
        let ((), handle) = Container::new()
            .unshare(Namespace::USER | Namespace::PID)
            .run_with_startup(
                Duration::from_secs(2),
                |context| {
                    assert_eq!(Pid::this(), parent);
                    assert_ne!(context.child_pid(), Pid::from_raw(1));
                    Ok(())
                },
                |_| {
                    assert_eq!(Pid::this().as_raw(), 1);
                    Ok(())
                },
                |()| (namespace_population_probe(), ()),
            )
            .unwrap();
        assert_eq!(
            handle.finalize_with_status(),
            Ok((baseline, ExitStatus::Exited(0)))
        );
        // Opposing control: a genuine in-child helper consumes a PID and must
        // change this exact observation. Do not normalize namespace identities.
        let wrong = Container::new()
            .unshare(Namespace::USER | Namespace::PID)
            .run(|| {
                std::thread::spawn(|| ()).join().unwrap();
                namespace_population_probe()
            })
            .unwrap();
        assert_eq!(wrong, (1, 3, 4));
        assert_ne!(wrong, baseline);
    }

    #[test]
    fn startup_precedes_seccomp_without_widening_the_filter() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use syscalls::Sysno;

        use super::seccomp::Action;
        use super::seccomp::FilterBuilder;
        let filter = || {
            FilterBuilder::new()
                .default_action(Action::Allow)
                .syscalls([
                    (Sysno::sendmsg, Action::Errno(Errno::EPERM)),
                    (Sysno::recvmsg, Action::Errno(Errno::EPERM)),
                    #[cfg(target_arch = "x86_64")]
                    (Sysno::poll, Action::Errno(Errno::EPERM)),
                    // Without a poll syscall, libc::poll uses ppoll.
                    #[cfg(not(target_arch = "x86_64"))]
                    (Sysno::ppoll, Action::Errno(Errno::EPERM)),
                    (Sysno::getppid, Action::Errno(Errno::EPERM)),
                ])
                .build()
        };
        let denied = || Errno::result(unsafe { libc::syscall(libc::SYS_getppid) });
        assert_eq!(
            Container::new().seccomp(filter()).run(denied),
            Ok(Err(Errno::EPERM))
        );
        let ((), handle) = Container::new()
            .seccomp(filter())
            .run_with_startup(
                Duration::from_secs(2),
                |_| Ok(()),
                |_| Ok(()),
                |()| (denied(), ()),
            )
            .unwrap();
        assert_eq!(
            handle.finalize_with_status(),
            Ok((Err(Errno::EPERM), ExitStatus::Exited(0)))
        );
    }

    #[test]
    fn startup_drains_large_result_before_deferred_cleanup_and_actual_wait() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let (pid, handle) = Container::new()
            .run_with_startup(
                Duration::from_secs(2),
                |context| Ok(context.child_pid()),
                |_| Ok(()),
                |()| (vec![42u8; 10 * 1024 * 1024], BlockingDrop { shared }),
            )
            .unwrap();
        assert_eq!(handle.provisional(), &vec![42u8; 10 * 1024 * 1024]);
        let shared_ref = unsafe { &*shared };
        while !shared_ref.started.load(Ordering::Acquire) {
            unsafe { libc::sched_yield() };
        }
        assert!(!shared_ref.finished.load(Ordering::Acquire));
        shared_ref.release.store(true, Ordering::Release);
        let (value, status) = handle.finalize_with_status().unwrap();
        assert_eq!(value, vec![42u8; 10 * 1024 * 1024]);
        assert_eq!(status, ExitStatus::Exited(0));
        assert!(shared_ref.finished.load(Ordering::Acquire));
        assert_reaped(pid);
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn startup_keeps_cleanup_failure_and_drop_reap_semantics() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (pid, handle) = Container::new()
            .run_with_startup(
                Duration::from_secs(2),
                |context| Ok(context.child_pid()),
                |_| Ok(()),
                |()| (42, ExitDuringDrop(71)),
            )
            .unwrap();
        assert_eq!(handle.provisional(), &42);
        assert_eq!(
            handle.finalize_with_status(),
            Err(RunError::ExitStatus(ExitStatus::Exited(71)))
        );
        assert_reaped(pid);
        let (pid, handle) = Container::new()
            .run_with_startup(
                Duration::from_secs(2),
                |context| Ok(context.child_pid()),
                |_| Ok(()),
                |()| (42, ()),
            )
            .unwrap();
        drop(handle);
        assert_reaped(pid);
    }

    #[test]
    fn startup_parent_refusal_cancels_owned_child_without_running_workload() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let mut pid = None;
        let result = Container::new().run_with_startup(
            Duration::from_secs(2),
            |context| {
                pid = Some(context.child_pid());
                Err::<(), _>(StartupError::Refused)
            },
            |_| Ok(()),
            |()| {
                unsafe { &*shared }.started.store(true, Ordering::Release);
                ((), ())
            },
        );
        assert!(matches!(
            result,
            Err(StartupRunError::Child {
                cause: StartupError::Refused,
                status: ExitStatus::Signaled(Signal::SIGKILL, false)
            })
        ));
        assert!(!unsafe { &*shared }.started.load(Ordering::Acquire));
        assert_reaped(pid.unwrap());
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn startup_child_setup_and_callback_refusals_are_not_readiness() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("absent");
        let result = Container::new().current_dir(missing).run_with_startup(
            Duration::from_secs(2),
            |_| -> Result<(), StartupError> {
                panic!("parent hook must not see failed child setup")
            },
            |_| -> Result<(), StartupError> { panic!("child hook must not see failed setup") },
            |()| -> ((), ()) { panic!("workload must not run") },
        );
        assert!(matches!(
            result,
            Err(StartupRunError::Child {
                cause: StartupError::Setup(Error { .. }),
                ..
            })
        ));
        if let Err(StartupRunError::Child {
            cause: StartupError::Setup(error),
            ..
        }) = result
        {
            assert_eq!(error, Error::new(Errno::ENOENT, Context::Chdir));
        }
        let result = Container::new().run_with_startup(
            Duration::from_secs(2),
            |_| -> Result<(), StartupError> {
                panic!("parent hook must not see refused child setup")
            },
            |_| Err::<(), _>(StartupError::Refused),
            |()| ((), ()),
        );
        assert!(matches!(
            result,
            Err(StartupRunError::Child {
                cause: StartupError::Refused,
                ..
            })
        ));
    }

    #[test]
    fn startup_premature_child_exit_retains_actual_status() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let result = Container::new().run_with_startup(
            Duration::from_secs(2),
            |_| Ok(()),
            |_| -> Result<(), StartupError> { unsafe { libc::_exit(73) } },
            |()| ((), ()),
        );
        assert!(matches!(
            result,
            Err(StartupRunError::Child {
                cause: StartupError::PeerClosed,
                status: ExitStatus::Exited(73)
            })
        ));
    }

    #[test]
    fn startup_deadline_kills_a_child_stuck_before_readiness() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let result = Container::new().run_with_startup(
            Duration::from_millis(100),
            |_| Ok(()),
            |_| -> Result<(), StartupError> {
                loop {
                    unsafe { libc::pause() };
                }
            },
            |()| ((), ()),
        );
        assert!(matches!(
            result,
            Err(StartupRunError::Child {
                cause: StartupError::TimedOut,
                status: ExitStatus::Signaled(Signal::SIGKILL, false)
            })
        ));
    }

    #[test]
    fn startup_late_parent_callback_cannot_release_workload() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let mut pid = None;
        let result = Container::new().run_with_startup(
            Duration::from_millis(100),
            |context| {
                pid = Some(context.child_pid());
                std::thread::sleep(Duration::from_millis(200));
                Ok(())
            },
            |_| Ok(()),
            |()| {
                unsafe { &*shared }.started.store(true, Ordering::Release);
                ((), ())
            },
        );
        assert!(matches!(
            result,
            Err(StartupRunError::Child {
                cause: StartupError::TimedOut,
                ..
            })
        ));
        assert!(!unsafe { &*shared }.started.load(Ordering::Acquire));
        assert_reaped(pid.unwrap());
        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn startup_invalid_timeout_refuses_before_clone_or_callbacks() {
        if crate::test_runs_in_own_process() {
            return;
        }
        for timeout in [Duration::ZERO, Duration::MAX] {
            let result = Container::new().run_with_startup(
                timeout,
                |_| -> Result<(), StartupError> { panic!("no parent callback") },
                |_| -> Result<(), StartupError> { panic!("no child callback") },
                |()| ((), ()),
            );
            assert!(matches!(
                result,
                Err(StartupRunError::BeforeClone(StartupError::InvalidTimeout))
            ));
        }
    }

    #[test]
    fn startup_protocol_rejects_malformed_wrong_phase_and_trailing_frames() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let good = {
            let mut frame = [0u8; STARTUP_FRAME_SIZE];
            frame[..4].copy_from_slice(b"RVS1");
            frame[4] = STARTUP_READY;
            frame
        };
        let mut cases = vec![
            vec![0],
            good[..STARTUP_FRAME_SIZE - 1].to_vec(),
            [good.as_slice(), &[0]].concat(),
        ];
        let mut wrong = good;
        wrong[4] = 3;
        cases.push(wrong.to_vec());
        let mut wrong = good;
        wrong[5] = 1;
        cases.push(wrong.to_vec());
        let mut wrong = good;
        wrong[7] = 1;
        cases.push(wrong.to_vec());
        for frame in cases {
            let (a, b) = StartupSocket::pair(Instant::now() + Duration::from_secs(2)).unwrap();
            assert_eq!(
                unsafe {
                    libc::send(
                        a.fd.as_raw_fd(),
                        frame.as_ptr().cast(),
                        frame.len(),
                        libc::MSG_NOSIGNAL,
                    )
                },
                frame.len() as isize
            );
            a.close_write().unwrap();
            let result = b.receive(Some(STARTUP_READY)).and_then(|_| b.receive(None));
            assert!(matches!(result, Err(StartupError::Protocol)));
        }
        let (a, b) = StartupSocket::pair(Instant::now() + Duration::from_secs(2)).unwrap();
        a.send(STARTUP_READY, &StartupFds::default(), None).unwrap();
        a.send(STARTUP_READY, &StartupFds::default(), None).unwrap();
        a.close_write().unwrap();
        b.receive(Some(STARTUP_READY)).unwrap();
        assert!(matches!(b.receive(None), Err(StartupError::Protocol)));
        let (a, b) = StartupSocket::pair(Instant::now() + Duration::from_secs(2)).unwrap();
        drop(a);
        assert!(matches!(
            b.receive(Some(STARTUP_READY)),
            Err(StartupError::PeerClosed)
        ));
    }

    #[test]
    fn startup_descriptor_cardinality_is_finite_and_refusal_closes_rights() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mut context = ChildStartContext {
            deadline: Instant::now() + Duration::from_secs(2),
            descriptors: StartupFds::default(),
            failure: None,
        };
        for _ in 0..MAX_STARTUP_FDS {
            context
                .transfer_fd(std::fs::File::open("/dev/null").unwrap().into())
                .unwrap();
        }
        let extra: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        let extra_number = extra.as_raw_fd();
        assert_eq!(context.transfer_fd(extra), Err(StartupError::Protocol));
        assert_eq!(unsafe { libc::fcntl(extra_number, libc::F_GETFD) }, -1);
        assert_eq!(Errno::last(), Errno::EBADF);
        let (a, b) = StartupSocket::pair(context.deadline).unwrap();
        a.send(STARTUP_REQUEST, &context.descriptors, None).unwrap();
        let received = b.receive(Some(STARTUP_REQUEST)).unwrap();
        assert_eq!(received.len, MAX_STARTUP_FDS);
        let numbers: Vec<_> = received
            .values
            .iter()
            .map(|fd| fd.as_ref().unwrap().as_raw_fd())
            .collect();
        drop(received);
        for fd in numbers {
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
            assert_eq!(Errno::last(), Errno::EBADF);
        }
    }

    #[test]
    fn can_panic() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let result = Container::new().run::<_, ()>(|| panic!());
        assert!(
            matches!(
                result,
                Err(RunError::ExitStatus(ExitStatus::Signaled(
                    Signal::SIGABRT,
                    _
                )))
            ),
            "Expected Err(ExitStatus(Signaled(SIGABRT, _))), got {:?}",
            result
        );
    }

    /// A `Container` child copies the descriptor table of the process that
    /// runs the test, and without an `execve` its `O_CLOEXEC` descriptors
    /// survive. In the libtest harness process that table holds the pipes and
    /// pidfds of tests running on other threads. The memfd opened here, only
    /// in the harness process, stands in for such a descriptor. The child must
    /// not hold it, which is true only when the test body runs in a process of
    /// its own.
    #[test]
    fn run_child_holds_no_descriptor_of_another_test() {
        use std::os::fd::FromRawFd;
        const NAME: &std::ffi::CStr = c"reverie-process-another-tests-descriptor";
        let _another_tests_descriptor = std::env::var_os(crate::ISOLATED_TEST_MARKER)
            .is_none()
            .then(|| {
                // SAFETY: NAME is NUL-terminated and the flags are valid.
                let fd = unsafe { libc::memfd_create(NAME.as_ptr(), libc::MFD_CLOEXEC) };
                assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
                // SAFETY: memfd_create just returned this descriptor to us alone.
                unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }
            });
        if crate::test_runs_in_own_process() {
            return;
        }
        let held = Container::new()
            .run(|| {
                let name = NAME.to_str().unwrap();
                std::fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter_map(|e| std::fs::read_link(e.path()).ok())
                    .map(|p| p.to_string_lossy().into_owned())
                    .filter(|p| p.contains(name))
                    .collect::<Vec<String>>()
            })
            .unwrap();
        assert_eq!(
            held,
            Vec::<String>::new(),
            "the child holds a descriptor that another test opened"
        );
    }

    #[test]
    fn is_new_process() {
        if crate::test_runs_in_own_process() {
            return;
        }
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
        if crate::test_runs_in_own_process() {
            return;
        }
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
        if crate::test_runs_in_own_process() {
            return;
        }
        assert_eq!(Container::new().run(|| 42), Ok(42));

        assert_eq!(
            Container::new().run(|| String::from("foobar")),
            Ok("foobar".into())
        );
    }

    struct BlockingDrop {
        shared: *mut SharedDropState,
    }

    impl Drop for BlockingDrop {
        fn drop(&mut self) {
            let shared = unsafe { &*self.shared };
            shared.started.store(true, Ordering::Release);
            while !shared.release.load(Ordering::Acquire) {
                unsafe { libc::sched_yield() };
            }
            shared.finished.store(true, Ordering::Release);
        }
    }

    struct SharedDropState {
        started: AtomicBool,
        release: AtomicBool,
        finished: AtomicBool,
    }

    fn new_shared_drop_state() -> (*mut libc::c_void, *mut SharedDropState) {
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<SharedDropState>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let shared = mapping.cast::<SharedDropState>();
        unsafe {
            shared.write(SharedDropState {
                started: AtomicBool::new(false),
                release: AtomicBool::new(false),
                finished: AtomicBool::new(false),
            });
        }
        (mapping, shared)
    }

    unsafe fn unmap_shared_drop_state(mapping: *mut libc::c_void, shared: *mut SharedDropState) {
        unsafe {
            std::ptr::drop_in_place(shared);
            assert_eq!(
                libc::munmap(mapping, std::mem::size_of::<SharedDropState>()),
                0
            );
        }
    }

    #[test]
    fn deferred_drop_publishes_result_before_cleanup_completes() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();

        let run = Container::new()
            .run_with_deferred_drop(|| (42, BlockingDrop { shared }))
            .unwrap();
        assert_eq!(run.provisional(), &42);

        let shared_ref = unsafe { &*shared };
        while !shared_ref.started.load(Ordering::Acquire) {
            unsafe { libc::sched_yield() };
        }
        shared_ref.release.store(true, Ordering::Release);
        assert_eq!(run.finalize(), Ok(42));
        assert!(shared_ref.finished.load(Ordering::Acquire));

        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    #[test]
    fn dropping_cleanup_handle_still_reaps_the_child() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let (mapping, shared) = new_shared_drop_state();
        let run = Container::new()
            .run_with_deferred_drop(|| ((), BlockingDrop { shared }))
            .unwrap();
        let shared_ref = unsafe { &*shared };
        while !shared_ref.started.load(Ordering::Acquire) {
            unsafe { libc::sched_yield() };
        }
        shared_ref.release.store(true, Ordering::Release);
        drop(run);
        assert!(shared_ref.finished.load(Ordering::Acquire));

        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    static WAITPID_SIGNAL_TEST: Mutex<()> = Mutex::new(());

    extern "C" fn ignore_test_signal(_signal: libc::c_int) {}

    #[test]
    fn deferred_finalize_retries_an_interrupted_wait_and_reaps() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let _serial = WAITPID_SIGNAL_TEST.lock().unwrap();
        WAITPID_ENTERED.store(false, Ordering::Release);
        WAITPID_INTERRUPTED.store(0, Ordering::Release);

        let action = SigAction::new(
            SigHandler::Handler(ignore_test_signal),
            SaFlags::empty(),
            SigSet::empty(),
        );
        let previous = unsafe { sigaction(Signal::SIGUSR2, &action) }.unwrap();

        let (mapping, shared) = new_shared_drop_state();
        let run = Container::new()
            .run_with_deferred_drop(|| (42, BlockingDrop { shared }))
            .unwrap();
        let child_pid = run.child.0.expect("deferred child pid");
        WAITPID_TEST_PID.store(child_pid.as_raw(), Ordering::Release);
        let waiting_thread = unsafe { libc::pthread_self() };
        let shared_address = shared as usize;
        let interrupter = std::thread::spawn(move || {
            while !WAITPID_ENTERED.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while WAITPID_INTERRUPTED.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
                assert_eq!(
                    unsafe { libc::pthread_kill(waiting_thread, libc::SIGUSR2) },
                    0
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            let shared = unsafe { &*(shared_address as *mut SharedDropState) };
            shared.release.store(true, Ordering::Release);
        });

        assert_eq!(run.finalize(), Ok(42));
        interrupter.join().unwrap();
        unsafe { sigaction(Signal::SIGUSR2, &previous) }.unwrap();
        WAITPID_TEST_PID.store(0, Ordering::Release);
        assert!(
            WAITPID_INTERRUPTED.load(Ordering::Acquire) > 0,
            "the signal did not interrupt waitpid"
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child_pid.as_raw(), &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(Errno::last(), Errno::ECHILD);

        unsafe { unmap_shared_drop_state(mapping, shared) };
    }

    struct ExitDuringDrop(i32);

    impl Drop for ExitDuringDrop {
        fn drop(&mut self) {
            unsafe { libc::_exit(self.0) }
        }
    }

    #[test]
    fn deferred_drop_exposes_cleanup_failure() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let run = Container::new()
            .run_with_deferred_drop(|| (42, ExitDuringDrop(71)))
            .unwrap();

        assert_eq!(run.provisional(), &42);
        assert_eq!(
            run.finalize(),
            Err(RunError::ExitStatus(ExitStatus::Exited(71)))
        );
    }

    #[test]
    fn mount_error_from_child_is_returned() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let source_dir = tempfile::tempdir().unwrap();
        let missing_source = source_dir.path().join("missing");

        let result = Container::new()
            .unshare(Namespace::USER | Namespace::MOUNT)
            .map_root()
            .mount(Mount::bind(missing_source, "/test"))
            .run(|| 42);

        assert_eq!(
            result,
            Err(RunError::Spawn(Error::new(Errno::ENOENT, Context::Mount)))
        );
    }

    #[test]
    fn test_directory_is_available_after_mount() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let result = Container::new()
            .unshare(Namespace::USER | Namespace::MOUNT)
            .map_root()
            .mount(Mount::tmpfs("/test").touch_target())
            .run(|| Path::new("/test").is_dir());

        assert_eq!(result, Ok(true));
    }

    /// A read-only bind of a source on a `nosuid`/`nodev` filesystem must work.
    ///
    /// ⚠️ REGRESSION TEST FOR A WHOLE LOST VALIDATE ARM, not a corner case.
    /// Inside a user namespace the kernel LOCKS the flags of mounts inherited
    /// from the parent namespace and refuses any remount that would clear one.
    /// A read-only bind is bind-then-remount, and the remount used to pass
    /// `MS_RDONLY` alone -- which asks to drop every other flag the source had.
    /// The mount returned EPERM and the container never spawned, so the guest
    /// did not fail, it never existed.
    ///
    /// Measured 2026-08-27: Hermit puts its frozen `/etc/group` and empty nscd
    /// directory in TMPDIR and binds each read-only, so a TMPDIR on
    /// `/run/user/<uid>` -- `nosuid,nodev` on any systemd host -- killed every
    /// container spawn. 610 of one arm's 612 e2e rows came from this one mount.
    ///
    /// ⚠️ THE SOURCE MUST BE MOUNTED BY THE HOST, NOT BY THIS CONTAINER. A tmpfs
    /// this test mounts itself lives in the container's own namespace, so its
    /// flags are NOT locked and the remount succeeds even unfixed -- a test that
    /// cannot fail. `/dev/shm` is host-mounted and carries both flags, so it
    /// reproduces the inheritance that makes them locked.
    #[test]
    fn a_readonly_bind_survives_a_nosuid_nodev_source() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let shm = Path::new("/dev/shm");
        // Fail closed rather than silently stop exercising the condition.
        let flags = nix::sys::statvfs::statvfs(shm).expect("statvfs /dev/shm");
        assert!(
            flags
                .flags()
                .contains(nix::sys::statvfs::FsFlags::ST_NOSUID)
                || flags.flags().contains(nix::sys::statvfs::FsFlags::ST_NODEV),
            "/dev/shm carries neither nosuid nor nodev on this host, so this test \
             would pass without exercising the locked-flag remount at all"
        );

        let source = tempfile::tempdir_in(shm).unwrap();
        let target = tempfile::tempdir().unwrap();

        let result = Container::new()
            .unshare(Namespace::USER | Namespace::MOUNT)
            .map_root()
            .mount(Mount::bind(source.path(), target.path()).readonly())
            .run(|| Path::new("/proc/self/mounts").is_file());

        assert_eq!(
            result,
            Ok(true),
            "a read-only bind whose source is nosuid/nodev must not fail; \
             EPERM here means the remount is dropping the source's locked flags"
        );
    }

    #[test]
    fn huge_return_value() {
        if crate::test_runs_in_own_process() {
            return;
        }
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
        if crate::test_runs_in_own_process() {
            return;
        }
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

    /// Pinning each guest to a different CPU must put it on a different CPU.
    ///
    /// ⚠️ THE IDENTIFIER THIS READS IS 32-BIT ON PURPOSE, AND AN 8-BIT ONE MADE
    /// THIS TEST UNPASSABLE ON THIS HOST. It used to read
    /// `get_feature_info().initial_local_apic_id()`, the LEGACY CPUID leaf 1
    /// `EBX[31:24]` field, which is a `u8` and so has 256 possible values.
    /// Measured at reverie main `b181b1bba20c846d277f500c25182a00e18add9a` on a
    /// 316-CPU host:
    ///
    /// ```text
    /// 316 observations, min id 0, max id 255, 256 distinct ids,
    /// exactly 60 ids seen twice -- and 316 - 256 = 60.
    /// ```
    ///
    /// So `max(count) == 1` could not hold for ANY amount of correct pinning,
    /// and the failure was deterministic rather than flaky. It had been
    /// recorded several times as "pre-existing and host-specific" and routinely
    /// skipped, which was true and left `validate.sh` step 2 red on main.
    ///
    /// ⚠️ BUT THE 256 CEILING IS NOT WHERE IT BREAKS, AND ASSUMING SO WOULD
    /// LEAVE THE NEXT READER ON A 64-CORE BOX BELIEVING THEY ARE SAFE. The
    /// legacy field drops the HIGH TOPOLOGY BITS, so ids repeat across sockets
    /// long before the count reaches 256: on this host the first collision is
    /// core 32 against core 0, both reporting id 0. Measured by enumerating
    /// only the first N cores with each identifier:
    ///
    /// ```text
    /// cores    16   32   33   64  128  256  316
    /// 8-bit    ok   ok  FAIL FAIL FAIL FAIL FAIL
    /// 32-bit   ok   ok   ok   ok   ok   ok   ok
    /// ```
    ///
    /// So this is not a test that was always broken. It is a test whose hidden
    /// assumption -- that the enumerated CPUs have distinct LEGACY apic ids --
    /// held on the smaller machines it was written against and stopped holding
    /// here, at 33 cores rather than at 257.
    ///
    /// CPUID leaf `0x0B` reports the 32-bit x2APIC id, which distinguishes as
    /// many CPUs as the machine has. Reading it does not weaken the assertion --
    /// the assertion is unchanged, and it is now able to fail for the reason it
    /// was written to catch instead of failing for arithmetic. Verified in that
    /// direction too: with affinity broken outright the repaired test reports
    /// `left: 316, right: 1`, and with affinity broken for half the cores it
    /// also fails.
    #[cfg(target_arch = "x86_64")]
    #[test]
    pub fn pin_affinity_to_all_cores() -> Result<(), Error> {
        if crate::test_runs_in_own_process() {
            return Ok(());
        }
        use std::collections::HashMap;

        use raw_cpuid::CpuId;

        let cpus = num_cpus::get();
        println!("Total cpus {}", cpus);

        // Map the x2APIC id to the number of times we observed it:
        let mut results: HashMap<u32, usize> = HashMap::new();
        for core in 0..cpus {
            println!("  Launching guest with affinity set to {}", core);
            let mut container = Container::new();
            container.affinity(core);
            let which_core = container
                .run(|| {
                    let cpuid = CpuId::new();
                    // Every level of leaf 0x0B reports the same x2APIC id for
                    // the executing logical processor, so the first is enough.
                    cpuid
                        .get_extended_topology_info()
                        .and_then(|mut levels| levels.next())
                        .map(|level| level.x2apic_id())
                })
                .unwrap();
            // ⚠️ REFUSE RATHER THAN FALL BACK TO THE 8-BIT FIELD. On a host
            // this large the legacy id provably cannot answer the question, so
            // silently using it would restore exactly the defect above.
            let which_core = which_core.unwrap_or_else(|| {
                panic!(
                    "CPUID leaf 0x0B (extended topology) is unavailable, so no \
                     32-bit x2APIC id can be read; with {cpus} CPUs the legacy \
                     8-bit APIC id cannot distinguish them and this test cannot \
                     decide anything"
                )
            });
            println!("    Guest sees its on x2APIC id {}", which_core);
            *results.entry(which_core).or_default() += 1;
        }

        println!("Final table size {:?}", results.len());
        assert_eq!(
            results.values().fold(0, |n, v| std::cmp::max(n, *v)),
            1,
            "two guests pinned to different CPUs reported the same x2APIC id, \
             so affinity did not place them on distinct CPUs"
        );
        Ok(())
    }
}
