/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The Tool's reserved directory (`LoadedStaticElf::tool_directory`), which
// must be on a read-only file system. Only an `O_DIRECTORY` open and a
// newfstatat of its exact path reach it, and only while that path still names
// it; every other path route to it, an open the kernel refuses for a
// directory, and every creation or removal of a name in it, fails with
// `ENOENT`, as for a name that does not exist, while procfs keeps `EACCES`,
// and the descriptors opened there work as any other. A final symbolic link
// spelled without a trailing slash is answered as Linux answers it: a named
// `O_CREAT` open with `O_EXCL` or `O_NOFOLLOW` finds the link itself, an
// `O_TMPFILE` open with `O_NOFOLLOW` finds no directory there (`ENOTDIR`),
// and a creation through it into the directory is the kernel's to answer,
// `EROFS`, for the read-only file system.
//
// An unprivileged test makes a read-only mount in a user and mount namespace
// of its own, so each test that reserves a directory runs its body in a child
// process of this test binary (`in_read_only_reservation`).

const TOOL_DIRECTORY_PATH: u64 = 0x100;
const TOOL_DIRECTORY_OTHER: u64 = 0x900;
const TOOL_DIRECTORY_EMPTY: u64 = 0xd00;
const TOOL_DIRECTORY_OUTPUT: u64 = 0x1000;

/// Between fork and exec: a new user namespace that maps the caller to root,
/// and a new mount namespace in which `<root>/reserved` is covered by an
/// empty read-only tmpfs and `<root>/elsewhere` by an empty writable one, so
/// that an ordinary directory beside the reservation is on a file system of
/// the same type.
struct ReservationNamespace {
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    reserved: CString,
    elsewhere: CString,
}

impl ReservationNamespace {
    fn new(root: &Path) -> Self {
        // SAFETY: geteuid and getegid have no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let path = |name: &str| CString::new(root.join(name).as_os_str().as_bytes()).unwrap();
        Self {
            uid_map: format!("0 {uid} 1").into_bytes(),
            gid_map: format!("0 {gid} 1").into_bytes(),
            reserved: path("reserved"),
            elsewhere: path("elsewhere"),
        }
    }

    fn write(path: &CStr, bytes: &[u8]) -> std::io::Result<()> {
        // SAFETY: path is NUL-terminated and bytes is a live buffer of its
        // length; the descriptor is closed before returning.
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let written = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
            let error = std::io::Error::last_os_error();
            libc::close(fd);
            if written != bytes.len() as isize {
                return Err(error);
            }
        }
        Ok(())
    }

    fn mount_tmpfs(target: &CStr, flags: libc::c_ulong) -> std::io::Result<()> {
        // SAFETY: the strings are NUL-terminated and live for the call.
        if unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                target.as_ptr(),
                c"tmpfs".as_ptr(),
                flags | libc::MS_NOSUID | libc::MS_NODEV,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Only system calls, and no allocation: this runs in the forked child.
    fn enter(&self) -> std::io::Result<()> {
        // SAFETY: unshare takes no pointers.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Self::write(c"/proc/self/setgroups", b"deny")?;
        Self::write(c"/proc/self/uid_map", &self.uid_map)?;
        Self::write(c"/proc/self/gid_map", &self.gid_map)?;
        Self::mount_tmpfs(&self.reserved, libc::MS_RDONLY)?;
        Self::mount_tmpfs(&self.elsewhere, 0)
    }
}

/// Run the calling test, `test`, in a child process of this test binary, in
/// a new user and mount namespace where `<root>/reserved` is an empty
/// read-only tmpfs and `<root>/elsewhere` a writable one
/// ([`ReservationNamespace`]). In that child, returns the root, where the
/// caller runs its body; in the parent, returns `None` once the child ran
/// exactly that test and it passed.
fn in_read_only_reservation(test: &str) -> Option<PathBuf> {
    const TEST: &str = "REVERIE_LINUXEMU_RESERVATION_TEST";
    const ROOT: &str = "REVERIE_LINUXEMU_RESERVATION_ROOT";
    if std::env::var(TEST).as_deref() == Ok(test) {
        let root = std::env::var_os(ROOT).expect("the parent names the root");
        return Some(PathBuf::from(root));
    }
    let root = TestDir::new();
    for directory in ["reserved", "elsewhere", "moved"] {
        std::fs::create_dir(root.0.join(directory)).unwrap();
    }
    let results = TestDir::new();
    let log = results.0.join("libtest.log");
    let module = module_path!()
        .split_once("::")
        .map_or(module_path!(), |(_, path)| path);
    let name = format!("{module}::{test}");
    let namespace = ReservationNamespace::new(&root.0);
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            &name,
            "--nocapture",
            "--test-threads=1",
            "--logfile",
        ])
        .arg(&log)
        .env(TEST, test)
        .env(ROOT, &root.0);
    // SAFETY: enter makes only system calls and allocates nothing.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut command, move || namespace.enter())
    };
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{test} in its namespace: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Exactly one completed, passing run of this test, and no other.
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        format!("ok {name}\n"),
        "{test}: the child's execution record"
    );
    None
}

struct ToolDirectoryFixture {
    root: PathBuf,
    memory: GuestMemory,
    state: LoadedStaticElf,
    reserved: PathBuf,
    reserved_mode: u32,
}

impl ToolDirectoryFixture {
    /// In the child [`in_read_only_reservation`] runs: `root` holds the
    /// read-only `reserved`, which is reserved, the writable `elsewhere`, a
    /// file and a link to the reservation.
    fn new(root: PathBuf) -> Self {
        let reserved = root.join("reserved");
        std::fs::write(root.join("file"), b"payload").unwrap();
        std::os::unix::fs::symlink(&reserved, root.join("link")).unwrap();
        let mut state = test_state(&root);
        state.tool_directory = Some(crate::elf::ToolDirectory::open(&reserved).unwrap());
        let reserved_mode = std::fs::metadata(&reserved).unwrap().permissions().mode();
        let memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        Self {
            root,
            memory,
            state,
            reserved,
            reserved_mode,
        }
    }

    fn call(&mut self, number: libc::c_long, args: [u64; 6]) -> i64 {
        syscall_result(&mut self.memory, &mut self.state, number, args)
    }

    fn path(&mut self, address: u64, path: &str) -> u64 {
        write_c_string(&mut self.memory, address, path);
        address
    }

    fn exact(&self) -> String {
        self.reserved.to_str().unwrap().to_owned()
    }

    /// What the executor answers for an open of `spelling` from `dirfd` with
    /// `flags` (and mode 0600), as [`native_open`] reports a native one: 0
    /// where it succeeds (the descriptor is closed), or the negative errno.
    fn open_answer(&mut self, dirfd: u64, spelling: &str, flags: i32) -> i64 {
        let path = self.path(TOOL_DIRECTORY_PATH, spelling);
        let fd = self.call(libc::SYS_openat, [dirfd, path, flags as u64, 0o600, 0, 0]);
        if fd >= 0 {
            assert_eq!(self.call(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]), 0);
            0
        } else {
            fd
        }
    }

    fn assert_reserved_untouched(&self) {
        assert_eq!(std::fs::read_dir(&self.reserved).unwrap().count(), 0);
        assert_eq!(
            std::fs::metadata(&self.reserved)
                .unwrap()
                .permissions()
                .mode(),
            self.reserved_mode
        );
        assert_eq!(std::fs::read(self.root.join("file")).unwrap(), b"payload");
    }
}

#[test]
fn tool_directory_is_hidden_from_every_other_path_route() {
    let Some(root) =
        in_read_only_reservation("tool_directory_is_hidden_from_every_other_path_route")
    else {
        return;
    };
    let mut f = ToolDirectoryFixture::new(root);
    let cwd = f.state.cwd.clone();
    let root_path = f.root.to_str().unwrap().to_owned();
    let root_path = f.path(TOOL_DIRECTORY_PATH, &root_path);
    let root = f.call(
        libc::SYS_openat,
        [
            libc::AT_FDCWD as u64,
            root_path,
            (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
            0,
            0,
            0,
        ],
    );
    assert!(root >= 3, "{root}");
    let at_fdcwd = libc::AT_FDCWD as u64;
    let enoent = negative_errno(libc::ENOENT);
    // The directory by a symbolic link, relative to the working directory, by
    // a `..` and relative to a descriptor: each lookup resolves to it.
    for (dirfd, spelling) in [
        (at_fdcwd, "link"),
        (at_fdcwd, "reserved"),
        (at_fdcwd, "reserved/"),
        (at_fdcwd, "elsewhere/../reserved"),
        (root as u64, "reserved"),
        (root as u64, "link"),
    ] {
        let path = f.path(TOOL_DIRECTORY_PATH, spelling);
        let what = format!("{spelling} from {dirfd:#x}");
        for flags in [
            libc::O_RDONLY | libc::O_DIRECTORY,
            libc::O_RDONLY,
            libc::O_PATH | libc::O_DIRECTORY,
            libc::O_PATH,
            libc::O_CREAT | libc::O_RDONLY,
            libc::O_CREAT | libc::O_WRONLY,
        ] {
            assert_eq!(
                f.call(libc::SYS_openat, [dirfd, path, flags as u64, 0o600, 0, 0]),
                enoent,
                "open {what} flags={flags:#x}"
            );
        }
        assert_eq!(
            f.call(
                libc::SYS_openat,
                [
                    dirfd,
                    path,
                    (libc::O_TMPFILE | libc::O_RDWR) as u64,
                    0o600,
                    0,
                    0
                ],
            ),
            enoent,
            "O_TMPFILE in {what}"
        );
        assert_eq!(
            f.call(
                libc::SYS_newfstatat,
                [dirfd, path, TOOL_DIRECTORY_OUTPUT, 0, 0, 0]
            ),
            enoent,
            "stat {what}"
        );
        assert_eq!(
            f.call(
                libc::SYS_statx,
                [
                    dirfd,
                    path,
                    0,
                    libc::STATX_BASIC_STATS as u64,
                    TOOL_DIRECTORY_OUTPUT,
                    0
                ],
            ),
            enoent,
            "statx {what}"
        );
        for mode in [libc::W_OK, libc::R_OK | libc::X_OK, libc::F_OK] {
            assert_eq!(
                f.call(libc::SYS_faccessat2, [dirfd, path, mode as u64, 0, 0, 0]),
                enoent,
                "access {what} mode={mode}"
            );
        }
        assert_eq!(
            f.call(libc::SYS_fchmodat, [dirfd, path, 0o555, 0, 0, 0]),
            enoent,
            "chmod {what}"
        );
        assert_eq!(
            f.call(libc::SYS_fchownat, [dirfd, path, 0, 0, 0, 0]),
            enoent,
            "chown {what}"
        );
        assert_eq!(
            f.call(libc::SYS_utimensat, [dirfd, path, 0, 0, 0, 0]),
            enoent,
            "utimes {what}"
        );
        if !spelling.ends_with("link") {
            // readlink of the directory itself; a link is read as the link.
            assert_eq!(
                f.call(
                    libc::SYS_readlinkat,
                    [dirfd, path, TOOL_DIRECTORY_OUTPUT, 64, 0, 0]
                ),
                enoent,
                "readlink {what}"
            );
        }
        // A new name below it, by every call that creates or removes one.
        let below = f.path(
            TOOL_DIRECTORY_OTHER,
            &format!("{}/new", spelling.trim_end_matches('/')),
        );
        let file = f.path(TOOL_DIRECTORY_EMPTY, "file");
        for (name, number, args) in [
            ("mkdirat", libc::SYS_mkdirat, [dirfd, below, 0o700, 0, 0, 0]),
            (
                "open O_CREAT",
                libc::SYS_openat,
                [
                    dirfd,
                    below,
                    (libc::O_CREAT | libc::O_WRONLY) as u64,
                    0o600,
                    0,
                    0,
                ],
            ),
            (
                "mknodat",
                libc::SYS_mknodat,
                [dirfd, below, (libc::S_IFIFO | 0o600) as u64, 0, 0, 0],
            ),
            (
                "symlinkat",
                libc::SYS_symlinkat,
                [file, dirfd, below, 0, 0, 0],
            ),
            (
                "linkat",
                libc::SYS_linkat,
                [at_fdcwd, file, dirfd, below, 0, 0],
            ),
            (
                "renameat",
                libc::SYS_renameat,
                [at_fdcwd, file, dirfd, below, 0, 0],
            ),
            ("unlinkat", libc::SYS_unlinkat, [dirfd, below, 0, 0, 0, 0]),
            (
                "rmdir",
                libc::SYS_unlinkat,
                [dirfd, below, libc::AT_REMOVEDIR as u64, 0, 0, 0],
            ),
        ] {
            assert_eq!(f.call(number, args), enoent, "{name} below {what}");
        }
        f.assert_reserved_untouched();
    }
    // The calls that name a path relative to the working directory only.
    for spelling in ["link", "reserved"] {
        let path = f.path(TOOL_DIRECTORY_PATH, spelling);
        let name = f.path(TOOL_DIRECTORY_OTHER, "user.reverie");
        for (call, number, args) in [
            (
                "statfs",
                libc::SYS_statfs,
                [path, TOOL_DIRECTORY_OUTPUT, 0, 0, 0, 0],
            ),
            ("chdir", libc::SYS_chdir, [path, 0, 0, 0, 0, 0]),
            ("truncate", libc::SYS_truncate, [path, 0, 0, 0, 0, 0]),
            (
                "getxattr",
                libc::SYS_getxattr,
                [path, name, TOOL_DIRECTORY_OUTPUT, 64, 0, 0],
            ),
            (
                "listxattr",
                libc::SYS_listxattr,
                [path, TOOL_DIRECTORY_OUTPUT, 64, 0, 0, 0],
            ),
            (
                "setxattr",
                libc::SYS_setxattr,
                [path, name, TOOL_DIRECTORY_EMPTY, 1, 0, 0],
            ),
            (
                "removexattr",
                libc::SYS_removexattr,
                [path, name, 0, 0, 0, 0],
            ),
        ] {
            assert_eq!(f.call(number, args), enoent, "{call} {spelling}");
        }
        let watcher = f.call(
            libc::SYS_inotify_init1,
            [libc::IN_NONBLOCK as u64, 0, 0, 0, 0, 0],
        );
        assert!(watcher >= 0, "{watcher}");
        assert_eq!(
            f.call(
                libc::SYS_inotify_add_watch,
                [watcher as u64, path, libc::IN_ALL_EVENTS as u64, 0, 0, 0]
            ),
            enoent,
            "inotify_add_watch {spelling}"
        );
        assert_eq!(f.call(libc::SYS_close, [watcher as u64, 0, 0, 0, 0, 0]), 0);
    }
    f.assert_reserved_untouched();
    // An O_PATH open creates nothing (Linux's build_open_how drops O_CREAT),
    // so it is a lookup like any other: what is missing is ENOENT, whatever
    // directory holds it.
    for spelling in ["link/new", "reserved/new"] {
        let path = f.path(TOOL_DIRECTORY_PATH, spelling);
        assert_eq!(
            f.call(
                libc::SYS_openat,
                [
                    at_fdcwd,
                    path,
                    (libc::O_PATH | libc::O_CREAT) as u64,
                    0o600,
                    0,
                    0
                ],
            ),
            enoent,
            "O_PATH|O_CREAT of {spelling}"
        );
    }
    // The working directory never moved into it.
    assert_eq!(f.state.cwd, cwd);
    // The directory itself is neither removed, renamed nor replaced.
    let reserved = f.path(TOOL_DIRECTORY_PATH, "reserved");
    let elsewhere = f.path(TOOL_DIRECTORY_OTHER, "elsewhere");
    for (call, number, args) in [
        (
            "rmdir",
            libc::SYS_unlinkat,
            [at_fdcwd, reserved, libc::AT_REMOVEDIR as u64, 0, 0, 0],
        ),
        (
            "unlink",
            libc::SYS_unlinkat,
            [at_fdcwd, reserved, 0, 0, 0, 0],
        ),
        (
            "rename from",
            libc::SYS_renameat,
            [at_fdcwd, reserved, at_fdcwd, elsewhere, 0, 0],
        ),
        (
            "rename over",
            libc::SYS_renameat,
            [at_fdcwd, elsewhere, at_fdcwd, reserved, 0, 0],
        ),
        (
            "exchange",
            libc::SYS_renameat2,
            [
                at_fdcwd,
                elsewhere,
                at_fdcwd,
                reserved,
                libc::RENAME_EXCHANGE as u64,
                0,
            ],
        ),
    ] {
        assert_eq!(f.call(number, args), enoent, "{call} the directory itself");
    }
    assert!(f.reserved.is_dir() && f.root.join("elsewhere").is_dir());
    f.assert_reserved_untouched();
    // procfs keeps its own answer.
    let procfs = f.path(TOOL_DIRECTORY_PATH, "/proc/sys");
    assert_eq!(
        f.call(
            libc::SYS_openat,
            [
                at_fdcwd,
                procfs,
                (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                0,
                0,
                0
            ],
        ),
        negative_errno(libc::EACCES),
        "procfs"
    );
    // A symbolic link to it is not the directory: removing it is an ordinary
    // unlink of the link.
    let link = f.path(TOOL_DIRECTORY_PATH, "link");
    assert_eq!(f.call(libc::SYS_unlinkat, [at_fdcwd, link, 0, 0, 0, 0]), 0);
    assert!(f.reserved.is_dir() && !f.root.join("link").exists());
    // An ordinary directory beside it, on a file system of the same type
    // (tmpfs), is unaffected.
    let elsewhere = f.path(TOOL_DIRECTORY_PATH, "elsewhere");
    let opened = f.call(
        libc::SYS_openat,
        [
            at_fdcwd,
            elsewhere,
            (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
            0,
            0,
            0,
        ],
    );
    assert!(opened >= 3, "{opened}");
    assert_eq!(
        f.call(
            libc::SYS_statfs,
            [elsewhere, TOOL_DIRECTORY_OUTPUT, 0, 0, 0, 0]
        ),
        0
    );
    let new = f.path(TOOL_DIRECTORY_OTHER, "elsewhere/new");
    assert_eq!(
        f.call(libc::SYS_mkdirat, [at_fdcwd, new, 0o700, 0, 0, 0]),
        0
    );
    assert!(f.root.join("elsewhere/new").is_dir());
}

#[test]
fn creation_through_a_final_link_into_the_reservation_answers_erofs() {
    let Some(root) = in_read_only_reservation(
        "creation_through_a_final_link_into_the_reservation_answers_erofs",
    ) else {
        return;
    };
    // The executor does not follow a creating open's final link: the kernel
    // does, and answers for the read-only mount the reservation requires. So
    // a link that dangles into the directory, by an absolute or a relative
    // target, through a second link, or up from another directory, from the
    // working directory or from a descriptor, creates nothing there.
    let mut f = ToolDirectoryFixture::new(root);
    let link = |target: String, name: &str| {
        std::os::unix::fs::symlink(target, f.root.join(name)).unwrap();
    };
    link(format!("{}/x", f.exact()), "dangling-absolute");
    link("reserved/x".into(), "dangling-relative");
    link("chain-second".into(), "chain-first");
    link(format!("{}/y", f.exact()), "chain-second");
    std::fs::create_dir(f.root.join("deeper")).unwrap();
    link("../reserved/z".into(), "deeper/dangling-up");
    let root_path = f.root.to_str().unwrap().to_owned();
    let root_path = f.path(TOOL_DIRECTORY_PATH, &root_path);
    let root = f.call(
        libc::SYS_openat,
        [
            libc::AT_FDCWD as u64,
            root_path,
            (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
            0,
            0,
            0,
        ],
    );
    assert!(root >= 3, "{root}");
    let at_fdcwd = libc::AT_FDCWD as u64;
    let erofs = negative_errno(libc::EROFS);
    for (dirfd, spelling) in [
        (at_fdcwd, "dangling-absolute"),
        (at_fdcwd, "dangling-relative"),
        (at_fdcwd, "chain-first"),
        (at_fdcwd, "deeper/dangling-up"),
        (root as u64, "dangling-relative"),
        (root as u64, "chain-first"),
    ] {
        let path = f.path(TOOL_DIRECTORY_PATH, spelling);
        for flags in [
            libc::O_CREAT | libc::O_WRONLY,
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            libc::O_CREAT | libc::O_RDONLY,
        ] {
            assert_eq!(
                f.call(libc::SYS_openat, [dirfd, path, flags as u64, 0o600, 0, 0]),
                erofs,
                "create through {spelling} from {dirfd:#x} flags={flags:#x}"
            );
        }
        if dirfd == at_fdcwd {
            assert_eq!(
                f.call(libc::SYS_creat, [path, 0o600, 0, 0, 0, 0]),
                erofs,
                "creat through {spelling}"
            );
        }
        // An O_EXCL or O_NOFOLLOW open finds the link itself, as on Linux.
        for (flags, errno) in [
            (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY, libc::EEXIST),
            (
                libc::O_CREAT | libc::O_NOFOLLOW | libc::O_WRONLY,
                libc::ELOOP,
            ),
        ] {
            assert_eq!(
                f.call(libc::SYS_openat, [dirfd, path, flags as u64, 0o600, 0, 0]),
                negative_errno(errno),
                "{spelling} from {dirfd:#x} flags={flags:#x}"
            );
        }
        f.assert_reserved_untouched();
    }
}

#[test]
fn tmpfile_through_a_final_link_keeps_linux_answers() {
    let Some(root) = in_read_only_reservation("tmpfile_through_a_final_link_keeps_linux_answers")
    else {
        return;
    };
    // O_TMPFILE resolves the directory it names as Linux does, its final
    // link followed unless the call has O_NOFOLLOW (do_tmpfile's lookup
    // with LOOKUP_DIRECTORY gives ENOTDIR for a link), while a directory is
    // reserved. Away from the reservation, each answer is the native one.
    let mut f = ToolDirectoryFixture::new(root);
    std::os::unix::fs::symlink(f.root.join("elsewhere"), f.root.join("link-elsewhere")).unwrap();
    let native = |path: &Path, flags: i32| {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is NUL-terminated; a returned descriptor is closed.
        let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
        if fd >= 0 {
            // SAFETY: open returned a new owned descriptor.
            unsafe { libc::close(fd) };
            0
        } else {
            -(std::io::Error::last_os_error().raw_os_error().unwrap() as i64)
        }
    };
    let at_fdcwd = libc::AT_FDCWD as u64;
    for (spelling, flags) in [
        ("link-elsewhere", libc::O_TMPFILE | libc::O_RDWR),
        (
            "link-elsewhere",
            libc::O_TMPFILE | libc::O_RDWR | libc::O_NOFOLLOW,
        ),
        (
            "elsewhere",
            libc::O_TMPFILE | libc::O_RDWR | libc::O_NOFOLLOW,
        ),
    ] {
        let expected = native(&f.root.join(spelling), flags);
        let path = f.path(TOOL_DIRECTORY_PATH, spelling);
        let fd = f.call(
            libc::SYS_openat,
            [at_fdcwd, path, flags as u64, 0o600, 0, 0],
        );
        let answer = if fd >= 0 {
            assert_eq!(f.call(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]), 0);
            0
        } else {
            fd
        };
        assert_eq!(answer, expected, "{spelling} flags={flags:#x}");
    }
    assert_eq!(
        native(
            &f.root.join("link-elsewhere"),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_NOFOLLOW
        ),
        negative_errno(libc::ENOTDIR)
    );
    // Through a link to the reservation: the directory is hidden; with
    // O_NOFOLLOW the link itself is no directory, as on Linux.
    let path = f.path(TOOL_DIRECTORY_PATH, "link");
    for (flags, errno) in [
        (libc::O_TMPFILE | libc::O_RDWR, libc::ENOENT),
        (
            libc::O_TMPFILE | libc::O_RDWR | libc::O_NOFOLLOW,
            libc::ENOTDIR,
        ),
    ] {
        assert_eq!(
            f.call(
                libc::SYS_openat,
                [at_fdcwd, path, flags as u64, 0o600, 0, 0]
            ),
            negative_errno(errno),
            "link flags={flags:#x}"
        );
    }
    f.assert_reserved_untouched();
}

#[test]
fn tool_directory_admits_only_its_exact_directory_open_and_stat() {
    let Some(root) =
        in_read_only_reservation("tool_directory_admits_only_its_exact_directory_open_and_stat")
    else {
        return;
    };
    let mut f = ToolDirectoryFixture::new(root);
    let at_fdcwd = libc::AT_FDCWD as u64;
    let enoent = negative_errno(libc::ENOENT);
    let exact = f.exact();
    let path = f.path(TOOL_DIRECTORY_PATH, &exact);
    let identity = std::fs::metadata(&f.reserved).unwrap();
    // A stat by the exact path reaches it, following a final link or not.
    for (number, args) in [
        (
            libc::SYS_newfstatat,
            [at_fdcwd, path, TOOL_DIRECTORY_OUTPUT, 0, 0, 0],
        ),
        (
            libc::SYS_newfstatat,
            [
                at_fdcwd,
                path,
                TOOL_DIRECTORY_OUTPUT,
                libc::AT_SYMLINK_NOFOLLOW as u64,
                0,
                0,
            ],
        ),
        (libc::SYS_stat, [path, TOOL_DIRECTORY_OUTPUT, 0, 0, 0, 0]),
    ] {
        assert_eq!(f.call(number, args), 0);
        let stat: libc::stat = read_struct(&f.memory, TOOL_DIRECTORY_OUTPUT);
        assert_eq!((stat.st_dev, stat.st_ino), (identity.dev(), identity.ino()));
    }
    // statx is no stat the exception names.
    assert_eq!(
        f.call(
            libc::SYS_statx,
            [
                at_fdcwd,
                path,
                0,
                libc::STATX_BASIC_STATS as u64,
                TOOL_DIRECTORY_OUTPUT,
                0
            ],
        ),
        enoent
    );
    // An open of it as a directory reaches it; any other open does not. An
    // O_PATH open's O_CREAT is dropped first, as on Linux.
    let mut descriptors = Vec::new();
    for flags in [
        libc::O_RDONLY | libc::O_DIRECTORY,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        libc::O_PATH | libc::O_DIRECTORY,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CREAT,
    ] {
        let fd = f.call(libc::SYS_openat, [at_fdcwd, path, flags as u64, 0, 0, 0]);
        assert!(fd >= 3, "flags={flags:#x}: {fd}");
        descriptors.push((fd as u64, flags & libc::O_PATH != 0));
    }
    for flags in [libc::O_RDONLY, libc::O_PATH, libc::O_CREAT | libc::O_RDONLY] {
        assert_eq!(
            f.call(libc::SYS_openat, [at_fdcwd, path, flags as u64, 0, 0, 0]),
            enoent,
            "flags={flags:#x}"
        );
    }
    assert_eq!(
        f.call(
            libc::SYS_openat,
            [
                at_fdcwd,
                path,
                (libc::O_TMPFILE | libc::O_RDWR) as u64,
                0o600,
                0,
                0
            ],
        ),
        enoent
    );
    // The other path calls by the exact path stay refused.
    let name = f.path(TOOL_DIRECTORY_OTHER, "user.reverie");
    for (call, number, args) in [
        (
            "statfs",
            libc::SYS_statfs,
            [path, TOOL_DIRECTORY_OUTPUT, 0, 0, 0, 0],
        ),
        ("chdir", libc::SYS_chdir, [path, 0, 0, 0, 0, 0]),
        (
            "access",
            libc::SYS_faccessat2,
            [at_fdcwd, path, libc::R_OK as u64, 0, 0, 0],
        ),
        (
            "getxattr",
            libc::SYS_getxattr,
            [path, name, TOOL_DIRECTORY_OUTPUT, 64, 0, 0],
        ),
        (
            "chmod",
            libc::SYS_fchmodat,
            [at_fdcwd, path, 0o555, 0, 0, 0],
        ),
    ] {
        assert_eq!(f.call(number, args), enoent, "{call} by the exact path");
    }
    let below = f.path(TOOL_DIRECTORY_OTHER, &format!("{exact}/new"));
    assert_eq!(
        f.call(libc::SYS_mkdirat, [at_fdcwd, below, 0o700, 0, 0, 0]),
        enoent
    );
    // Its descriptors work as any other: the calls that name them are not
    // refused, but a working directory in it is, and so is every path
    // looked up from it that resolves to it or creates a name in it.
    let empty = f.path(TOOL_DIRECTORY_EMPTY, "");
    for (fd, path_only) in descriptors {
        assert_eq!(
            f.call(libc::SYS_fstat, [fd, TOOL_DIRECTORY_OUTPUT, 0, 0, 0, 0]),
            0
        );
        let stat: libc::stat = read_struct(&f.memory, TOOL_DIRECTORY_OUTPUT);
        assert_eq!((stat.st_dev, stat.st_ino), (identity.dev(), identity.ino()));
        assert_eq!(
            f.call(
                libc::SYS_newfstatat,
                [
                    fd,
                    empty,
                    TOOL_DIRECTORY_OUTPUT,
                    libc::AT_EMPTY_PATH as u64,
                    0,
                    0
                ],
            ),
            0
        );
        if !path_only {
            assert_eq!(
                f.call(libc::SYS_fstatfs, [fd, TOOL_DIRECTORY_OUTPUT, 0, 0, 0, 0]),
                0
            );
            let listed = f.call(
                libc::SYS_getdents64,
                [fd, TOOL_DIRECTORY_OUTPUT, 512, 0, 0, 0],
            );
            assert!(listed > 0, "{listed}");
            assert_eq!(f.call(libc::SYS_fchdir, [fd, 0, 0, 0, 0, 0]), enoent);
        }
        let dot = f.path(TOOL_DIRECTORY_OTHER, ".");
        assert_eq!(
            f.call(
                libc::SYS_openat,
                [
                    fd,
                    dot,
                    (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                    0,
                    0,
                    0
                ],
            ),
            enoent
        );
        let new = f.path(TOOL_DIRECTORY_OTHER, "new");
        assert_eq!(f.call(libc::SYS_mkdirat, [fd, new, 0o700, 0, 0, 0]), enoent);
        assert_eq!(
            f.call(
                libc::SYS_openat,
                [fd, new, (libc::O_CREAT | libc::O_RDWR) as u64, 0o600, 0, 0],
            ),
            enoent
        );
        // Its parent is an ordinary directory.
        let parent = f.path(TOOL_DIRECTORY_OTHER, "..");
        let opened = f.call(
            libc::SYS_openat,
            [
                fd,
                parent,
                (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                0,
                0,
                0,
            ],
        );
        assert!(opened >= 3, "{opened}");
        assert_eq!(f.call(libc::SYS_close, [opened as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(f.call(libc::SYS_close, [fd, 0, 0, 0, 0, 0]), 0);
    }
    f.assert_reserved_untouched();
}

#[test]
fn tool_directory_admissions_fail_closed_once_its_path_is_covered() {
    let Some(root) =
        in_read_only_reservation("tool_directory_admissions_fail_closed_once_its_path_is_covered")
    else {
        return;
    };
    let mut f = ToolDirectoryFixture::new(root);
    let at_fdcwd = libc::AT_FDCWD as u64;
    let enoent = negative_errno(libc::ENOENT);
    let c_path = |path: &Path| CString::new(path.as_os_str().as_bytes()).unwrap();
    let (reserved, moved) = (c_path(&f.reserved), c_path(&f.root.join("moved")));
    // The reserved directory is bound to another path, and another read-only
    // tmpfs then covers its own path.
    // SAFETY: the strings are NUL-terminated and live for the calls.
    unsafe {
        assert_eq!(
            libc::mount(
                reserved.as_ptr(),
                moved.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null()
            ),
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            libc::mount(
                c"tmpfs".as_ptr(),
                reserved.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_RDONLY,
                std::ptr::null()
            ),
            0,
            "{}",
            std::io::Error::last_os_error()
        );
    }
    let exact = f.exact();
    let path = f.path(TOOL_DIRECTORY_PATH, &exact);
    for flags in [
        libc::O_RDONLY | libc::O_DIRECTORY,
        libc::O_PATH | libc::O_DIRECTORY,
    ] {
        assert_eq!(
            f.call(libc::SYS_openat, [at_fdcwd, path, flags as u64, 0, 0, 0]),
            enoent,
            "exact open flags={flags:#x} of a covered path"
        );
    }
    for flags in [0, libc::AT_SYMLINK_NOFOLLOW] {
        assert_eq!(
            f.call(
                libc::SYS_newfstatat,
                [at_fdcwd, path, TOOL_DIRECTORY_OUTPUT, flags as u64, 0, 0],
            ),
            enoent,
            "exact newfstatat flags={flags:#x} of a covered path"
        );
    }
    // The reserved directory itself stays hidden at its other path.
    let moved = f.path(TOOL_DIRECTORY_OTHER, "moved");
    assert_eq!(
        f.call(
            libc::SYS_openat,
            [
                at_fdcwd,
                moved,
                (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                0,
                0,
                0
            ],
        ),
        enoent
    );
    assert_eq!(
        f.call(
            libc::SYS_newfstatat,
            [at_fdcwd, moved, TOOL_DIRECTORY_OUTPUT, 0, 0, 0],
        ),
        enoent
    );
}

#[test]
fn tool_directory_reservation_needs_a_read_only_mount() {
    if let Some(root) =
        in_read_only_reservation("tool_directory_reservation_needs_a_read_only_mount")
    {
        // The empty read-only tmpfs is accepted.
        let reserved = crate::elf::ToolDirectory::open(&root.join("reserved")).unwrap();
        assert_eq!(reserved.path(), root.join("reserved").as_path());
        return;
    }
    let root = TestDir::new();
    std::fs::write(root.0.join("file"), b"").unwrap();
    let errno = |path: &Path| {
        crate::elf::ToolDirectory::open(path)
            .unwrap_err()
            .raw_os_error()
    };
    assert_eq!(errno(Path::new("relative")), Some(libc::EINVAL));
    assert_eq!(errno(Path::new("/proc")), Some(libc::EINVAL));
    assert_eq!(errno(&root.0.join("file")), Some(libc::ENOTDIR));
    assert_eq!(errno(&root.0.join("missing")), Some(libc::ENOENT));
    // A writable directory is refused: nothing must be creatable in a
    // reservation by any route.
    let writable = crate::elf::ToolDirectory::open(&root.0).unwrap_err();
    assert_eq!(writable.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        writable.to_string().contains("read-only file system"),
        "{writable}"
    );
}

#[test]
fn a_read_only_bind_of_a_writable_file_system_is_refused() {
    let Some(root) =
        in_read_only_reservation("a_read_only_bind_of_a_writable_file_system_is_refused")
    else {
        return;
    };
    // The file system must be read-only, not only the mount: through another
    // mount of a writable file system a name could still be created in the
    // directory, past the executor (a creation through a final link to it,
    // say). fstatvfs reports ST_RDONLY for both, so the superblock decides.
    let c_path = |path: &Path| CString::new(path.as_os_str().as_bytes()).unwrap();
    let mount = |source: Option<&Path>, target: &Path, kind: Option<&CStr>, flags, data: &CStr| {
        let source = source.map(c_path);
        let target = c_path(target);
        // SAFETY: every string is NUL-terminated and lives across the call.
        let mounted = unsafe {
            libc::mount(
                source
                    .as_ref()
                    .map_or(c"none".as_ptr(), |source| source.as_ptr()),
                target.as_ptr(),
                kind.map_or(std::ptr::null(), CStr::as_ptr),
                flags,
                data.as_ptr().cast(),
            )
        };
        assert_eq!(mounted, 0, "{}", std::io::Error::last_os_error());
    };
    let read_only_mount = |path: &Path| {
        let path = c_path(path);
        let mut status = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
        // SAFETY: path is NUL-terminated and status is writable.
        assert_eq!(
            unsafe { libc::statvfs(path.as_ptr(), status.as_mut_ptr()) },
            0
        );
        // SAFETY: statvfs initialized status on success.
        unsafe { status.assume_init() }.f_flag & libc::ST_RDONLY != 0
    };
    for directory in ["fresh", "bound-read-only", "bound-writable"] {
        std::fs::create_dir(root.join(directory)).unwrap();
    }
    // A fresh tmpfs mounted read-only, of mode 0555 with one inode and no
    // set-user-ID, device or executable files: accepted.
    let fresh = root.join("fresh");
    mount(
        None,
        &fresh,
        Some(c"tmpfs"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        c"mode=0555,size=4k,nr_inodes=1",
    );
    assert_eq!(
        crate::elf::ToolDirectory::open(&fresh).unwrap().path(),
        fresh.as_path()
    );
    // A read-only bind of the read-only tmpfs is that same read-only file
    // system: accepted.
    let bound_read_only = root.join("bound-read-only");
    mount(
        Some(&root.join("reserved")),
        &bound_read_only,
        None,
        libc::MS_BIND,
        c"",
    );
    mount(
        None,
        &bound_read_only,
        None,
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
        c"",
    );
    assert!(crate::elf::ToolDirectory::open(&bound_read_only).is_ok());
    // A read-only bind of the writable tmpfs: the mount is read-only, the
    // file system is not, and a name made through the writable mount appears
    // in it. Refused.
    let bound_writable = root.join("bound-writable");
    mount(
        Some(&root.join("elsewhere")),
        &bound_writable,
        None,
        libc::MS_BIND,
        c"",
    );
    mount(
        None,
        &bound_writable,
        None,
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
        c"",
    );
    assert!(read_only_mount(&bound_writable) && read_only_mount(&fresh));
    std::fs::write(root.join("elsewhere/made-elsewhere"), b"").unwrap();
    assert!(bound_writable.join("made-elsewhere").exists());
    std::fs::remove_file(root.join("elsewhere/made-elsewhere")).unwrap();
    let refused = crate::elf::ToolDirectory::open(&bound_writable).unwrap_err();
    assert_eq!(
        refused.kind(),
        std::io::ErrorKind::InvalidInput,
        "{refused}"
    );
    assert!(
        refused.to_string().contains("read-only file system"),
        "{refused}"
    );
}

#[test]
fn creating_opens_with_o_excl_or_o_nofollow_find_a_final_link_to_the_reservation() {
    let Some(root) = in_read_only_reservation(
        "creating_opens_with_o_excl_or_o_nofollow_find_a_final_link_to_the_reservation",
    ) else {
        return;
    };
    // With O_EXCL (which implies O_NOFOLLOW) or O_NOFOLLOW, Linux's creating
    // open stops at a final symbolic link, wherever it points: EEXIST or
    // ELOOP. A link to the reserved directory answers so too, as a link to
    // an ordinary directory does natively; the directory itself, by its name
    // and with a trailing slash, stays hidden.
    let mut f = ToolDirectoryFixture::new(root);
    std::os::unix::fs::symlink(f.root.join("elsewhere"), f.root.join("link-elsewhere")).unwrap();
    let native = native_open;
    let root_path = f.root.to_str().unwrap().to_owned();
    let root_path = f.path(TOOL_DIRECTORY_PATH, &root_path);
    let root = f.call(
        libc::SYS_openat,
        [
            libc::AT_FDCWD as u64,
            root_path,
            (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
            0,
            0,
            0,
        ],
    );
    assert!(root >= 3, "{root}");
    let at_fdcwd = libc::AT_FDCWD as u64;
    for (flags, errno) in [
        (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY, libc::EEXIST),
        (libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, libc::EEXIST),
        (
            libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_WRONLY,
            libc::EEXIST,
        ),
        (
            libc::O_CREAT | libc::O_NOFOLLOW | libc::O_WRONLY,
            libc::ELOOP,
        ),
        (
            libc::O_CREAT | libc::O_NOFOLLOW | libc::O_RDONLY,
            libc::ELOOP,
        ),
    ] {
        assert_eq!(
            native(&f.root.join("link-elsewhere"), flags),
            negative_errno(errno),
            "native link-elsewhere flags={flags:#x}"
        );
        for dirfd in [at_fdcwd, root as u64] {
            let path = f.path(TOOL_DIRECTORY_PATH, "link");
            assert_eq!(
                f.call(libc::SYS_openat, [dirfd, path, flags as u64, 0o600, 0, 0]),
                negative_errno(errno),
                "link from {dirfd:#x} flags={flags:#x}"
            );
            // Away from the reservation, with it active, the executor
            // answers as native Linux does.
            assert_eq!(
                f.open_answer(dirfd, "link-elsewhere", flags),
                native(&f.root.join("link-elsewhere"), flags),
                "link-elsewhere from {dirfd:#x} flags={flags:#x}"
            );
        }
        for spelling in ["reserved", "reserved/"] {
            let path = f.path(TOOL_DIRECTORY_PATH, spelling);
            assert_eq!(
                f.call(
                    libc::SYS_openat,
                    [at_fdcwd, path, flags as u64, 0o600, 0, 0]
                ),
                negative_errno(libc::ENOENT),
                "{spelling} flags={flags:#x}"
            );
        }
        f.assert_reserved_untouched();
    }
    // Without either flag a creating open follows the link: to an ordinary
    // directory it answers EISDIR, natively and through the executor alike.
    for flags in [
        libc::O_CREAT | libc::O_WRONLY,
        libc::O_CREAT | libc::O_RDONLY,
    ] {
        assert_eq!(
            native(&f.root.join("link-elsewhere"), flags),
            negative_errno(libc::EISDIR),
            "native link-elsewhere flags={flags:#x}"
        );
        for dirfd in [at_fdcwd, root as u64] {
            assert_eq!(
                f.open_answer(dirfd, "link-elsewhere", flags),
                negative_errno(libc::EISDIR),
                "link-elsewhere from {dirfd:#x} flags={flags:#x}"
            );
        }
    }
    f.assert_reserved_untouched();
}

#[test]
fn opens_the_kernel_refuses_for_the_reservation_fail_as_for_a_missing_name() {
    let Some(root) = in_read_only_reservation(
        "opens_the_kernel_refuses_for_the_reservation_fail_as_for_a_missing_name",
    ) else {
        return;
    };
    // Linux refuses a write mode or O_TRUNC on a directory (EISDIR), and
    // O_DIRECT where the file system cannot do it (EINVAL), before the
    // executor's check of the opened object could run. On a route to the
    // reserved directory such an open fails as every other one does, as for
    // a name that does not exist. With O_NOFOLLOW the open stops at a final
    // link, as on Linux (ELOOP).
    let mut f = ToolDirectoryFixture::new(root);
    std::os::unix::fs::symlink(f.root.join("elsewhere"), f.root.join("link-elsewhere")).unwrap();
    let native = native_open;
    let root_path = f.root.to_str().unwrap().to_owned();
    let root_path = f.path(TOOL_DIRECTORY_PATH, &root_path);
    let root = f.call(
        libc::SYS_openat,
        [
            libc::AT_FDCWD as u64,
            root_path,
            (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
            0,
            0,
            0,
        ],
    );
    assert!(root >= 3, "{root}");
    let at_fdcwd = libc::AT_FDCWD as u64;
    let refused_by_the_kernel = [
        libc::O_WRONLY,
        libc::O_RDWR,
        libc::O_RDONLY | libc::O_TRUNC,
        libc::O_WRONLY | libc::O_DIRECTORY,
        libc::O_RDONLY | libc::O_DIRECT,
    ];
    for flags in &refused_by_the_kernel[..4] {
        assert_eq!(
            native(&f.root.join("link-elsewhere"), *flags),
            negative_errno(libc::EISDIR),
            "native link-elsewhere flags={flags:#x}"
        );
    }
    // Away from the reservation, with it active, the executor answers each
    // of these as native Linux does (EISDIR for the first four).
    for flags in refused_by_the_kernel {
        for dirfd in [at_fdcwd, root as u64] {
            assert_eq!(
                f.open_answer(dirfd, "link-elsewhere", flags),
                native(&f.root.join("link-elsewhere"), flags),
                "link-elsewhere from {dirfd:#x} flags={flags:#x}"
            );
        }
    }
    let exact = f.exact();
    for (dirfd, spelling) in [
        (at_fdcwd, "link"),
        (at_fdcwd, "reserved"),
        (at_fdcwd, "reserved/"),
        (at_fdcwd, "elsewhere/../reserved"),
        (at_fdcwd, exact.as_str()),
        (root as u64, "reserved"),
        (root as u64, "link"),
    ] {
        let path = f.path(TOOL_DIRECTORY_PATH, spelling);
        for flags in refused_by_the_kernel {
            if spelling == exact && flags & libc::O_DIRECTORY != 0 {
                // The exact path's admitted directory open reaches it, and
                // gets what Linux answers for any directory.
                assert_eq!(
                    f.call(libc::SYS_openat, [dirfd, path, flags as u64, 0, 0, 0]),
                    negative_errno(libc::EISDIR),
                    "the exact path flags={flags:#x}"
                );
                continue;
            }
            assert_eq!(
                f.call(libc::SYS_openat, [dirfd, path, flags as u64, 0, 0, 0]),
                negative_errno(libc::ENOENT),
                "{spelling} from {dirfd:#x} flags={flags:#x}"
            );
        }
    }
    for flags in [
        libc::O_RDONLY | libc::O_NOFOLLOW,
        libc::O_WRONLY | libc::O_NOFOLLOW,
    ] {
        assert_eq!(
            native(&f.root.join("link-elsewhere"), flags),
            negative_errno(libc::ELOOP)
        );
        assert_eq!(
            f.open_answer(at_fdcwd, "link-elsewhere", flags),
            negative_errno(libc::ELOOP),
            "link-elsewhere flags={flags:#x}"
        );
        let path = f.path(TOOL_DIRECTORY_PATH, "link");
        assert_eq!(
            f.call(libc::SYS_openat, [at_fdcwd, path, flags as u64, 0, 0, 0]),
            negative_errno(libc::ELOOP),
            "link flags={flags:#x}"
        );
    }
    f.assert_reserved_untouched();
}

/// What a native `open` of `path` with `flags` (and mode 0600) answers: 0
/// where it succeeds (the descriptor is closed), or the negative errno.
fn native_open(path: &Path, flags: i32) -> i64 {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: path is NUL-terminated; a returned descriptor is closed.
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
    if fd >= 0 {
        // SAFETY: open returned a new owned descriptor.
        unsafe { libc::close(fd) };
        0
    } else {
        -(std::io::Error::last_os_error().raw_os_error().unwrap() as i64)
    }
}
