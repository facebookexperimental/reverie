/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// An exec resolves its filename as Linux's execve does (fs/exec.c
// do_open_execat): an absolute name from the root and any other name, with
// or without a slash, from the working directory, which is the directory
// itself and not its recorded path; execve never searches PATH. It execs
// only a regular file its caller may execute. Each case is checked against
// Linux's own answer for the same raw execve where one exists
// (`native_execve`): Rust's `Command` searches PATH for a bare name, so it
// cannot be the oracle for one.

/// Guest addresses of the exec request's path, argv, envp and strings.
const NATIVE_RESOLUTION_PATH_ADDRESS: u64 = 0x200;
const NATIVE_RESOLUTION_ARGV_ADDRESS: u64 = 0x1200;
const NATIVE_RESOLUTION_ENVP_ADDRESS: u64 = 0x1300;
const NATIVE_RESOLUTION_STRINGS_ADDRESS: u64 = 0x2000;

/// Writes `execve(path, ["name"], envp)` into `memory` and returns the
/// request. argv[0] is a fixed UTF-8 name: this executor reads argv as UTF-8,
/// and the filename may not be.
fn native_resolution_exec_request(
    memory: &mut GuestMemory,
    path: &[u8],
    envp: &[&str],
) -> SyscallRequest {
    let path = CString::new(path).unwrap();
    memory
        .write(NATIVE_RESOLUTION_PATH_ADDRESS, path.as_bytes_with_nul())
        .unwrap();
    memory
        .write(NATIVE_RESOLUTION_STRINGS_ADDRESS, b"name\0")
        .unwrap();
    memory
        .write(
            NATIVE_RESOLUTION_ARGV_ADDRESS,
            &NATIVE_RESOLUTION_STRINGS_ADDRESS.to_le_bytes(),
        )
        .unwrap();
    memory
        .write(NATIVE_RESOLUTION_ARGV_ADDRESS + 8, &0_u64.to_le_bytes())
        .unwrap();
    let mut cursor = NATIVE_RESOLUTION_STRINGS_ADDRESS + 8;
    let mut words = Vec::new();
    for entry in envp {
        let entry = CString::new(*entry).unwrap();
        memory.write(cursor, entry.as_bytes_with_nul()).unwrap();
        words.push(cursor);
        cursor += entry.as_bytes_with_nul().len() as u64;
    }
    words.push(0);
    for (index, word) in words.into_iter().enumerate() {
        memory
            .write(
                NATIVE_RESOLUTION_ENVP_ADDRESS + 8 * index as u64,
                &word.to_le_bytes(),
            )
            .unwrap();
    }
    SyscallRequest::new(
        libc::SYS_execve as u64,
        [
            NATIVE_RESOLUTION_PATH_ADDRESS,
            NATIVE_RESOLUTION_ARGV_ADDRESS,
            NATIVE_RESOLUTION_ENVP_ADDRESS,
            0,
            0,
            0,
        ],
    )
}

/// Execs `name` with `envp` from an executor over `state`.
fn native_resolution_exec(
    state: LoadedStaticElf,
    name: &[u8],
    envp: &[&str],
) -> ExecInterpreterOutcome {
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let request = native_resolution_exec_request(&mut memory, name, envp);
    let mut executor = ElfExecutor::new(state, false);
    let result = executor.execute_process_action(&request, &memory);
    ExecInterpreterOutcome {
        result,
        refusal: executor.take_unsupported_refusal(),
        action: executor.take_process_action(),
    }
}

/// The image of the exec `outcome` published.
fn native_resolution_published_image(outcome: ExecInterpreterOutcome, what: &str) -> Vec<u8> {
    assert_eq!(
        outcome.result,
        Some(0),
        "{what}: refusal {:?}",
        outcome.refusal
    );
    assert_eq!(outcome.refusal, None, "{what}");
    let Some(ProcessAction::Exec { image, .. }) = outcome.action else {
        panic!("{what}: no exec was published");
    };
    image
}

/// Linux's own answer to a raw `execve(name, [name], envp)` from the
/// directory `cwd` holds: `Ok(exit code)` or `Err(errno)`. The child only
/// calls fchdir, execve and _exit, which are async-signal-safe.
fn native_execve(cwd: &std::fs::File, name: &[u8], envp: &[&str]) -> Result<i32, i32> {
    let name = CString::new(name).unwrap();
    let envp = envp
        .iter()
        .map(|entry| CString::new(*entry).unwrap())
        .collect::<Vec<_>>();
    let argv = [name.as_ptr(), std::ptr::null()];
    let envp = envp
        .iter()
        .map(|entry| entry.as_ptr())
        .chain([std::ptr::null()])
        .collect::<Vec<_>>();
    let cwd = cwd.as_raw_fd();
    // SAFETY: the child calls only fchdir, execve and _exit, with arguments
    // built before the fork.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
    if child == 0 {
        // SAFETY: async-signal-safe calls on live arguments; _exit never returns.
        unsafe {
            if libc::fchdir(cwd) != 0 {
                libc::_exit(99);
            }
            libc::execve(name.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(100 + *libc::__errno_location());
        }
    }
    let mut status = 0;
    // SAFETY: waitpid writes only `status` for the child this test forked.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status), "native child status {status:#x}");
    match libc::WEXITSTATUS(status) {
        99 => panic!("native child could not fchdir"),
        code if code >= 100 => Err(code - 100),
        code => Ok(code),
    }
}

/// Writes a static program that exits 0 at `path`, mode 0700.
fn native_resolution_write_program(path: &Path) -> Vec<u8> {
    let image = crate::elf::minimal_test_elf(&EXEC_INTERPRETER_EXIT_ZERO);
    host_resources_write_executable(path, &image);
    image
}

/// A state whose running program is a distinct file with the image "own
/// image", so an exec that wrongly runs the caller's own exe link succeeds
/// with that image instead of failing.
fn native_resolution_state_with_own_image(root: &Path) -> LoadedStaticElf {
    let own = root.join("own-image");
    if !own.exists() {
        std::fs::write(&own, b"own image").unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut state = test_state(root);
    state.executable_file = Some(Arc::new(std::fs::File::open(&own).unwrap()));
    state.executable_image = Arc::new(b"own image".to_vec());
    state
}

/// The number of components of the absolute `path`: as many `..` lead from
/// it to the root.
fn native_resolution_depth(path: &Path) -> usize {
    path.components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .count()
}

/// A bare name is resolved against the working directory, keeps its
/// spelling, and a symlink is named by the link.
#[test]
fn a_bare_name_resolves_against_the_working_directory() {
    let root = TestDir::new();
    let image = native_resolution_write_program(&root.0.join("cwd-program"));
    std::os::unix::fs::symlink(root.0.join("cwd-program"), root.0.join("alias")).unwrap();
    let cwd = std::fs::File::open(&root.0).unwrap();
    assert_eq!(native_execve(&cwd, b"cwd-program", &[]), Ok(0));

    let state = test_state(&root.0);
    let resolved = resolve_guest_exec_image(&state, b"cwd-program".to_vec(), &mut None).unwrap();
    assert_eq!(resolved.path, Path::new("cwd-program"));
    let resolved = resolve_guest_exec_image(&state, b"alias".to_vec(), &mut None).unwrap();
    assert_eq!(resolved.path, Path::new("alias"));
    assert_eq!(resolved.image, image);
    assert_eq!(
        native_resolution_published_image(
            native_resolution_exec(state, b"cwd-program", &[]),
            "cwd-program"
        ),
        image
    );
}

/// glibc's execvp and posix_spawnp try a bare name first for an empty PATH
/// entry (`PATH=:<dir>`) and expect ENOENT unless the working directory
/// holds it; execve itself never searches.
#[test]
fn an_empty_path_entry_is_not_searched_by_execve() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("bin")).unwrap();
    native_resolution_write_program(&root.0.join("bin/prog"));
    let path = format!("PATH=:{}", root.0.join("bin").display());
    let cwd = std::fs::File::open(&root.0).unwrap();
    assert_eq!(native_execve(&cwd, b"prog", &[&path]), Err(libc::ENOENT));
    exec_interpreter_assert_refused(
        native_resolution_exec(test_state(&root.0), b"prog", &[&path]),
        libc::ENOENT,
        "execve(\"prog\") with PATH=:<bin>",
    );
}

/// With no PATH in the environment a bare name is still only the working
/// directory's: a host program on the default search list is not run.
#[test]
fn a_bare_name_with_no_path_is_not_searched() {
    assert!(Path::new("/usr/bin/sh").exists() || Path::new("/bin/sh").exists());
    let root = TestDir::new();
    let cwd = std::fs::File::open(&root.0).unwrap();
    assert_eq!(native_execve(&cwd, b"sh", &[]), Err(libc::ENOENT));
    assert_eq!(
        resolve_guest_exec_image(&test_state(&root.0), b"sh".to_vec(), &mut None).unwrap_err(),
        negative_errno(libc::ENOENT)
    );
}

/// A PATH naming descriptor directories is never searched: a bare name
/// that is not in the working directory is ENOENT.
#[test]
fn a_path_naming_descriptor_directories_is_not_searched() {
    let root = TestDir::new();
    std::fs::write(root.0.join("secret"), b"secret").unwrap();
    let planted = exec_interpreter_plant(&std::fs::File::open(root.0.join("secret")).unwrap());
    let state = test_state(&root.0);
    assert!(host_fd(&state, planted.as_raw_fd()).is_none());
    let name = planted.as_raw_fd().to_string();
    for directory in ["/proc/self/fd", "/dev/fd", "/proc/thread-self/fd"] {
        let path = format!("PATH={directory}");
        exec_interpreter_assert_refused(
            native_resolution_exec(test_state(&root.0), name.as_bytes(), &[&path]),
            libc::ENOENT,
            &format!("execve(\"{name}\") with {path}"),
        );
    }
}

/// Names whose resolution differs from a PATH search, each against Linux's
/// answer: the empty name, a trailing slash after a file or nothing, `.`
/// and `..` (directories), and a name that is not UTF-8.
#[test]
fn exec_name_edge_cases_match_linux() {
    let root = TestDir::new();
    native_resolution_write_program(&root.0.join("prog"));
    native_resolution_write_program(&root.0.join(std::ffi::OsStr::from_bytes(b"\xff")));
    let cwd = std::fs::File::open(&root.0).unwrap();
    for (name, expected) in [
        (&b"prog/"[..], Err(libc::ENOTDIR)),
        (b"absent/", Err(libc::ENOENT)),
        (b".", Err(libc::EACCES)),
        (b"..", Err(libc::EACCES)),
        (b"\xff", Ok(0)),
    ] {
        let label = String::from_utf8_lossy(name).into_owned();
        assert_eq!(native_execve(&cwd, name, &[]), expected, "{label} natively");
        let outcome = native_resolution_exec(test_state(&root.0), name, &[]);
        match expected {
            Ok(_) => {
                native_resolution_published_image(outcome, &label);
            }
            Err(errno) => exec_interpreter_assert_refused(outcome, errno, &label),
        }
    }
    // The empty name: execve(2) gives ENOENT.
    assert_eq!(
        native_resolution_exec(test_state(&root.0), b"", &[]).result,
        Some(negative_errno(libc::ENOENT))
    );
}

/// A directory is not a program: EACCES (fs/namei.c may_open under
/// MAY_EXEC; fs/exec.c do_open_execat), by its absolute name, through a
/// symlink and by its bare name.
#[test]
fn exec_of_a_directory_is_eacces() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("dir")).unwrap();
    std::os::unix::fs::symlink(root.0.join("dir"), root.0.join("dirlink")).unwrap();
    let cwd = std::fs::File::open(&root.0).unwrap();
    for name in [
        root.0.join("dir").into_os_string().into_vec(),
        root.0.join("dirlink").into_os_string().into_vec(),
        b"dir".to_vec(),
    ] {
        let label = String::from_utf8_lossy(&name).into_owned();
        assert_eq!(
            native_execve(&cwd, &name, &[]),
            Err(libc::EACCES),
            "{label} natively"
        );
        exec_interpreter_assert_refused(
            native_resolution_exec(test_state(&root.0), &name, &[]),
            libc::EACCES,
            &label,
        );
    }
}

/// A FIFO is not a program: EACCES, and it is never opened, so the exec
/// cannot block waiting for a writer. The exec runs on a thread with a
/// bounded wait, so a regression fails instead of hanging the suite.
#[test]
fn exec_of_a_fifo_is_eacces_and_never_opens_it() {
    let root = TestDir::new();
    let fifo = root.0.join("fifo");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: mkfifo reads only the NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o700) }, 0);
    let cwd = std::fs::File::open(&root.0).unwrap();
    assert_eq!(
        native_execve(&cwd, fifo.as_os_str().as_bytes(), &[]),
        Err(libc::EACCES)
    );

    let (sender, receiver) = std::sync::mpsc::channel();
    let directory = root.0.clone();
    let name = fifo.as_os_str().as_bytes().to_vec();
    let worker = std::thread::spawn(move || {
        let outcome = native_resolution_exec(test_state(&directory), &name, &[]);
        let _ = sender.send((outcome.result, outcome.refusal, outcome.action.is_none()));
    });
    match receiver.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok((result, refusal, unpublished)) => {
            worker.join().unwrap();
            assert_eq!(result, Some(negative_errno(libc::EACCES)), "{refusal:?}");
            assert_eq!(refusal, None);
            assert!(unpublished, "an exec of a FIFO was published");
        }
        Err(_) => {
            // The exec opened the FIFO for reading and blocks for a writer:
            // be one, so the worker ends, then fail.
            for _ in 0..500 {
                // SAFETY: open reads only the NUL-terminated path.
                let writer =
                    unsafe { libc::open(fifo_c.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
                if writer >= 0 {
                    // SAFETY: open just returned this descriptor.
                    unsafe { libc::close(writer) };
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let _ = receiver.recv_timeout(std::time::Duration::from_secs(5));
            panic!("the exec of a FIFO opened it");
        }
    }
}

/// A character device is not a program: EACCES before any read, from the
/// type check or, for /dev/zero, which has no execute bit, the permission
/// check. An isolated child runs the exec under a lowered address-space
/// limit, so a regression that reads /dev/zero fails there instead of
/// exhausting memory.
#[test]
fn exec_of_a_device_is_eacces_and_never_reads_it() {
    const TEST: &str = "exec_of_a_device_is_eacces_and_never_reads_it";
    if !host_resources_is_child(TEST) {
        return host_resources_run_isolated(TEST);
    }
    let root = TestDir::new();
    let cwd = std::fs::File::open(&root.0).unwrap();
    assert_eq!(native_execve(&cwd, b"/dev/zero", &[]), Err(libc::EACCES));
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let request = native_resolution_exec_request(&mut memory, b"/dev/zero", &[]);
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let headroom = (HOST_RESOURCES_MEMORY + 64 * 1024 * 1024) as u64;
    let ((result, refusal, action), _) =
        host_resources_with_address_space_headroom(headroom, || {
            let result = executor.execute_process_action(&request, &memory);
            (
                result,
                executor.take_unsupported_refusal(),
                executor.take_process_action(),
            )
        });
    exec_interpreter_assert_refused(
        ExecInterpreterOutcome {
            result,
            refusal,
            action,
        },
        libc::EACCES,
        "/dev/zero",
    );
}

/// A symlink to a regular program runs the program, named by the link.
#[test]
fn exec_through_a_symlink_to_a_regular_file_runs_it() {
    let root = TestDir::new();
    let image = native_resolution_write_program(&root.0.join("target"));
    let alias = root.0.join("alias");
    std::os::unix::fs::symlink(root.0.join("target"), &alias).unwrap();
    let outcome = native_resolution_exec(test_state(&root.0), alias.as_os_str().as_bytes(), &[]);
    let Some(ProcessAction::Exec {
        executable_path,
        image: published,
        ..
    }) = outcome.action
    else {
        panic!("no exec was published: {:?}", outcome.result);
    };
    assert_eq!(executable_path, alias);
    assert_eq!(published, image);
}

/// A `#!` interpreter that is a directory is EACCES too: each level is
/// opened as a program is (fs/binfmt_script.c load_script calls open_exec).
#[test]
fn a_script_interpreter_that_is_a_directory_is_eacces() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("dir")).unwrap();
    let script = root.0.join("script");
    host_resources_write_executable(
        &script,
        format!("#!{}\n", root.0.join("dir").display()).as_bytes(),
    );
    let cwd = std::fs::File::open(&root.0).unwrap();
    assert_eq!(
        native_execve(&cwd, script.as_os_str().as_bytes(), &[]),
        Err(libc::EACCES)
    );
    exec_interpreter_assert_refused(
        native_resolution_exec(test_state(&root.0), script.as_os_str().as_bytes(), &[]),
        libc::EACCES,
        "script whose interpreter is a directory",
    );
}

/// A program its caller may not execute is EACCES (fs/exec.c
/// do_open_execat): mode 0644, which root may not execute either, and mode
/// 0411, which its owner may read but not execute, judged by Linux's answer
/// for this caller (a check for any execute bit would run it). A program the
/// caller may execute but not read (mode 0111) runs on Linux and is EACCES
/// here, a documented limit, wherever this process may not read it: the
/// image is read through a descriptor opened for reading.
#[test]
fn a_program_the_caller_may_not_execute_is_eacces() {
    let root = TestDir::new();
    let cwd = std::fs::File::open(&root.0).unwrap();
    for (name, mode) in [
        ("mode-0644", 0o644),
        ("mode-0411", 0o411),
        ("mode-0111", 0o111),
    ] {
        let path = root.0.join(name);
        native_resolution_write_program(&path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let native = native_execve(&cwd, path.as_os_str().as_bytes(), &[]);
        let outcome = native_resolution_exec(test_state(&root.0), path.as_os_str().as_bytes(), &[]);
        match (mode, native) {
            (0o111, Ok(0)) => {
                if std::fs::File::open(&path).is_ok() {
                    // This process may read it (root, with DAC override).
                    native_resolution_published_image(outcome, name);
                } else {
                    exec_interpreter_assert_refused(outcome, libc::EACCES, name);
                }
            }
            (_, Err(errno)) => exec_interpreter_assert_refused(outcome, errno, name),
            (_, Ok(code)) => {
                assert_eq!(code, 0, "{name} natively");
                native_resolution_published_image(outcome, name);
            }
        }
    }
}

/// An exec after the working directory was renamed runs: the loader takes
/// the task's working-directory handle, not its stale recorded path. (The
/// new image keeps the execing task's working directory either way.)
#[test]
fn an_exec_after_the_working_directory_is_renamed_runs() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("sub")).unwrap();
    let image = native_resolution_write_program(&root.0.join("prog"));
    let state = test_state(&root.0.join("sub"));
    std::fs::rename(root.0.join("sub"), root.0.join("moved")).unwrap();
    assert_eq!(
        native_resolution_published_image(
            native_resolution_exec(state, root.0.join("prog").as_os_str().as_bytes(), &[]),
            "exec after the cwd was renamed"
        ),
        image
    );
}

/// An exec from a removed working directory runs, as on Linux, which never
/// consults the working directory for an absolute filename.
#[test]
fn an_exec_from_a_removed_working_directory_runs() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("sub")).unwrap();
    let image = native_resolution_write_program(&root.0.join("prog"));
    let state = test_state(&root.0.join("sub"));
    std::fs::remove_dir(root.0.join("sub")).unwrap();
    assert_eq!(
        native_resolution_published_image(
            native_resolution_exec(state, root.0.join("prog").as_os_str().as_bytes(), &[]),
            "exec from a removed cwd"
        ),
        image
    );
}

/// A link planted over the stale recorded name of the working directory is
/// never followed: the exec runs, and the loader's working directory is the
/// task's own handle, not the planted directory.
#[test]
fn an_exec_never_follows_a_link_planted_over_the_stale_cwd_name() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("sub")).unwrap();
    std::fs::create_dir(root.0.join("other")).unwrap();
    let image = native_resolution_write_program(&root.0.join("prog"));
    let state = test_state(&root.0.join("sub"));
    std::fs::rename(root.0.join("sub"), root.0.join("moved")).unwrap();
    let planted = exec_interpreter_plant(&std::fs::File::open(root.0.join("other")).unwrap());
    std::os::unix::fs::symlink(
        format!("/proc/self/fd/{}", planted.as_raw_fd()),
        root.0.join("sub"),
    )
    .unwrap();
    let loaded = crate::elf::load_static_elf_image_of(
        &mut GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap(),
        &image,
        Some(Arc::new(std::fs::File::open(root.0.join("prog")).unwrap())),
        None,
        None,
        &["prog"],
        &[],
        &state.fs_context,
    )
    .expect("the load takes the task's working-directory handle");
    let loaded_cwd = exec_interpreter_identity(loaded.fs_context.cwd_fd.metadata().unwrap());
    assert_eq!(
        loaded_cwd,
        exec_interpreter_identity(std::fs::metadata(root.0.join("moved")).unwrap())
    );
    assert_ne!(
        loaded_cwd,
        exec_interpreter_identity(std::fs::metadata(root.0.join("other")).unwrap())
    );
    assert_eq!(
        native_resolution_published_image(
            native_resolution_exec(state, root.0.join("prog").as_os_str().as_bytes(), &[]),
            "exec with a link over the stale cwd name"
        ),
        image
    );
}

/// A relative name is resolved against the working directory itself, as
/// Linux resolves it, not against its recorded path: after the directory is
/// renamed it still runs its own program, and after a new directory takes
/// the old name, the new directory's program is not the one run.
#[test]
fn a_relative_name_resolves_against_the_working_directory_itself() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("d")).unwrap();
    let image = native_resolution_write_program(&root.0.join("d/prog"));
    let state = test_state(&root.0.join("d"));
    std::fs::rename(root.0.join("d"), root.0.join("d.old")).unwrap();
    let cwd = std::fs::File::open(root.0.join("d.old")).unwrap();
    assert_eq!(native_execve(&cwd, b"./prog", &[]), Ok(0));
    let resolved = resolve_guest_exec_image(&state, b"./prog".to_vec(), &mut None).unwrap();
    assert_eq!(resolved.image, image, "renamed working directory");

    std::fs::create_dir(root.0.join("d")).unwrap();
    std::fs::write(root.0.join("d/prog"), b"another program").unwrap();
    std::fs::set_permissions(
        root.0.join("d/prog"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let resolved = resolve_guest_exec_image(&state, b"prog".to_vec(), &mut None).unwrap();
    assert_eq!(resolved.image, image, "a new directory under the old name");
}

/// A relative name whose climb physically reaches the root and then names an
/// fd link is answered by the guest's descriptor table, as its absolute
/// spelling is: a held descriptor is ELOOP, a number the guest does not hold
/// is ENOENT, a name below a held directory is the file below it, and the
/// caller's own exe link is its own image.
#[test]
fn a_relative_fd_link_spelling_is_answered_by_the_guests_table() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("lib")).unwrap();
    let below = native_resolution_write_program(&root.0.join("lib/prog"));
    let own = root.0.join("own-image");
    std::fs::write(&own, b"own image").unwrap();
    std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
    let planted = exec_interpreter_plant(&std::fs::File::open(&own).unwrap());
    let mut state = test_state(&root.0);
    state.executable_file = Some(Arc::new(std::fs::File::open(&own).unwrap()));
    state.executable_image = Arc::new(b"own image".to_vec());
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let held = guest_open(&mut memory, &mut state, "own-image", libc::O_RDONLY);
    assert!(held >= 0, "open own-image: {held}");
    let directory = guest_open(&mut memory, &mut state, "lib", libc::O_RDONLY);
    assert!(directory >= 0, "open lib: {directory}");
    let up = "../".repeat(native_resolution_depth(&root.0));
    let resolve = |name: String| resolve_guest_exec_image(&state, name.into_bytes(), &mut None);

    assert_eq!(
        resolve(format!("{up}proc/self/fd/{held}")).unwrap_err(),
        negative_errno(libc::ELOOP)
    );
    assert_eq!(
        resolve(format!("{up}proc/self/fd/{}", planted.as_raw_fd())).unwrap_err(),
        negative_errno(libc::ENOENT)
    );
    assert_eq!(
        resolve(format!("{up}proc/self/fd/{directory}/prog"))
            .unwrap()
            .image,
        below
    );
    let resolved = resolve(format!("{up}proc/self/exe")).unwrap();
    assert!(Arc::ptr_eq(
        resolved.file.as_ref().unwrap(),
        state.executable_file.as_ref().unwrap()
    ));
    assert_eq!(resolved.image, b"own image");
}

/// A relative name is looked up from the working directory itself, so the
/// directory's recorded path, which can be stale, plays no part. Here the
/// directory moved deeper, so a name that climbs from it reaches a real
/// `proc/self/fd/<n>` program, which Linux runs, and so does this executor,
/// with no lexical step that could take the name for an fd link.
#[test]
fn a_relative_name_from_a_moved_working_directory_resolves_as_linux_does() {
    let root = TestDir::new();
    let depth = native_resolution_depth(&root.0);
    std::fs::create_dir(root.0.join("w")).unwrap();
    let state = test_state(&root.0.join("w"));
    let mut deeper = root.0.clone();
    for level in 0..depth {
        deeper.push(format!("d{level}"));
    }
    std::fs::create_dir_all(&deeper).unwrap();
    std::fs::rename(root.0.join("w"), deeper.join("w")).unwrap();
    let number = exec_interpreter_free_number();
    std::fs::create_dir_all(root.0.join("proc/self/fd")).unwrap();
    let image = native_resolution_write_program(&root.0.join(format!("proc/self/fd/{number}")));
    let name = format!("{}proc/self/fd/{number}", "../".repeat(depth + 1));
    let cwd = std::fs::File::open(deeper.join("w")).unwrap();
    assert_eq!(
        native_execve(&cwd, name.as_bytes(), &[]),
        Ok(0),
        "Linux runs the real file"
    );
    assert_eq!(
        native_resolution_published_image(
            native_resolution_exec(state, name.as_bytes(), &[]),
            "relative name from a moved working directory"
        ),
        image
    );
}

/// The same with a descriptor the guest holds at the number the stale path
/// would name: the name is still the real file Linux runs, not the file
/// below the guest's descriptor.
#[test]
fn a_relative_name_from_a_moved_working_directory_ignores_a_held_descriptor() {
    let root = TestDir::new();
    let depth = native_resolution_depth(&root.0);
    std::fs::create_dir(root.0.join("w")).unwrap();
    std::fs::create_dir(root.0.join("held")).unwrap();
    native_resolution_write_program(&root.0.join("held/prog"));
    let mut state = test_state(&root.0.join("w"));
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let held = guest_open(&mut memory, &mut state, "../held", libc::O_RDONLY);
    assert!(held >= 0, "open held: {held}");
    let mut deeper = root.0.clone();
    for level in 0..depth {
        deeper.push(format!("d{level}"));
    }
    std::fs::create_dir_all(&deeper).unwrap();
    std::fs::rename(root.0.join("w"), deeper.join("w")).unwrap();
    std::fs::create_dir_all(root.0.join(format!("proc/self/fd/{held}"))).unwrap();
    let real = root.0.join(format!("proc/self/fd/{held}/prog"));
    native_resolution_write_program(&real);
    let name = format!("{}proc/self/fd/{held}/prog", "../".repeat(depth + 1));
    let cwd = std::fs::File::open(deeper.join("w")).unwrap();
    assert_eq!(native_execve(&cwd, name.as_bytes(), &[]), Ok(0), "natively");
    let resolved = resolve_guest_exec_image(&state, name.into_bytes(), &mut None).unwrap();
    assert_eq!(
        exec_interpreter_identity(resolved.file.as_ref().unwrap().metadata().unwrap()),
        exec_interpreter_identity(std::fs::metadata(&real).unwrap()),
        "the real file, not the one below the held descriptor"
    );
    assert_ne!(
        exec_interpreter_identity(std::fs::metadata(&real).unwrap()),
        exec_interpreter_identity(std::fs::metadata(root.0.join("held/prog")).unwrap())
    );
}

/// A `..` is the parent of the directory the walk has reached, not of the
/// name before it: a spelling whose `..` follows a missing name is ENOENT,
/// and one whose `..` follows a regular file is ENOTDIR, as Linux answers,
/// even where folding the `..` away would leave the caller's exe link.
#[test]
fn a_dot_dot_after_a_missing_name_or_a_file_is_answered_as_linux_does() {
    let root = TestDir::new();
    let depth = native_resolution_depth(&root.0);
    let file = root.0.join("file");
    std::fs::write(&file, b"data").unwrap();
    let cwd = std::fs::File::open(&root.0).unwrap();
    let up = "../".repeat(depth + 1);
    for (name, errno) in [
        (
            format!("{}/missing/{up}proc/self/exe", root.0.display()),
            libc::ENOENT,
        ),
        (
            format!("{}/file/{up}proc/self/exe", root.0.display()),
            libc::ENOTDIR,
        ),
        (format!("missing/{up}proc/self/exe"), libc::ENOENT),
        (format!("file/{up}proc/self/exe"), libc::ENOTDIR),
    ] {
        assert_eq!(
            native_execve(&cwd, name.as_bytes(), &[]),
            Err(errno),
            "{name} natively"
        );
        exec_interpreter_assert_refused(
            native_resolution_exec(
                native_resolution_state_with_own_image(&root.0),
                name.as_bytes(),
                &[],
            ),
            errno,
            &name,
        );
    }
}

/// A `..` after a symbolic link climbs from the directory the link names,
/// as Linux walks it: the program found is the one beside that directory,
/// and a climb that a lexical fold would end at the root ends where the walk
/// does.
#[test]
fn a_dot_dot_after_a_symlink_climbs_from_its_target() {
    let root = TestDir::new();
    let depth = native_resolution_depth(&root.0);
    std::fs::create_dir_all(root.0.join("a/b")).unwrap();
    let image = native_resolution_write_program(&root.0.join("a/prog"));
    std::os::unix::fs::symlink(root.0.join("a/b"), root.0.join("l")).unwrap();
    let cwd = std::fs::File::open(&root.0).unwrap();
    for name in [
        format!("{}/l/../prog", root.0.display()),
        "l/../prog".to_string(),
    ] {
        assert_eq!(
            native_execve(&cwd, name.as_bytes(), &[]),
            Ok(0),
            "{name} natively"
        );
        assert_eq!(
            native_resolution_published_image(
                native_resolution_exec(test_state(&root.0), name.as_bytes(), &[]),
                &name
            ),
            image,
            "{name}"
        );
    }
    // From `l` a lexical fold of depth + 1 `..` reaches the root; the walk,
    // from a/b, stops one directory below it, where there is no proc/self/exe.
    let name = format!(
        "{}/l/{}proc/self/exe",
        root.0.display(),
        "../".repeat(depth + 1)
    );
    assert_eq!(
        native_execve(&cwd, name.as_bytes(), &[]),
        Err(libc::ENOENT),
        "natively"
    );
    exec_interpreter_assert_refused(
        native_resolution_exec(
            native_resolution_state_with_own_image(&root.0),
            name.as_bytes(),
            &[],
        ),
        libc::ENOENT,
        &name,
    );
}

/// A `..` at the root stays at the root (fs/namei.c follow_dotdot), so
/// climbing past it and back down finds the program, as Linux does. The root
/// is this process's: this executor has no separate guest root.
#[test]
fn a_dot_dot_above_the_root_stays_at_the_root() {
    let root = TestDir::new();
    let depth = native_resolution_depth(&root.0);
    let image = native_resolution_write_program(&root.0.join("prog"));
    let cwd = std::fs::File::open(&root.0).unwrap();
    let relative = root.0.strip_prefix("/").unwrap().display().to_string();
    for name in [
        format!("/../../{relative}/prog"),
        format!("{}{relative}/prog", "../".repeat(depth + 3)),
    ] {
        assert_eq!(
            native_execve(&cwd, name.as_bytes(), &[]),
            Ok(0),
            "{name} natively"
        );
        assert_eq!(
            native_resolution_published_image(
                native_resolution_exec(test_state(&root.0), name.as_bytes(), &[]),
                &name
            ),
            image,
            "{name}"
        );
    }
}

/// An fd-link spelling followed by `..` climbs from the file the guest's
/// descriptor names, as Linux follows the magic link and then `..`: the
/// program beside the held directory runs, in the /proc/self/fd, /dev/fd and
/// relative-climb forms (native Ok(0)). A number the guest does not hold is
/// ENOENT.
#[test]
fn an_fd_link_followed_by_dot_dot_climbs_from_the_guests_file() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("held")).unwrap();
    let program = root.0.join("prog");
    native_resolution_write_program(&program);
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let guest = guest_open(&mut memory, &mut state, "held", libc::O_RDONLY);
    assert!(guest >= 0, "open held: {guest}");
    let host = host_fd(&state, guest as libc::c_int).expect("the guest's descriptor");
    let cwd = std::fs::File::open(&root.0).unwrap();
    let up = "../".repeat(native_resolution_depth(&root.0));
    for (guest_name, native_name) in [
        (
            format!("/proc/self/fd/{guest}/../prog"),
            format!("/proc/self/fd/{host}/../prog"),
        ),
        (
            format!("/dev/fd/{guest}/../prog"),
            format!("/dev/fd/{host}/../prog"),
        ),
        (
            format!("/proc/self/fd/{guest}/..//prog"),
            format!("/proc/self/fd/{host}/..//prog"),
        ),
        (
            format!("{up}proc/self/fd/{guest}/../prog"),
            format!("{up}proc/self/fd/{host}/../prog"),
        ),
    ] {
        assert_eq!(
            native_execve(&cwd, native_name.as_bytes(), &[]),
            Ok(0),
            "{native_name} natively"
        );
        let resolved = resolve_guest_exec_image(&state, guest_name.clone().into_bytes(), &mut None)
            .unwrap_or_else(|errno| panic!("{guest_name}: {errno}"));
        assert_eq!(
            exec_interpreter_identity(resolved.file.as_ref().unwrap().metadata().unwrap()),
            exec_interpreter_identity(std::fs::metadata(&program).unwrap()),
            "{guest_name}"
        );
    }
    let free = exec_interpreter_free_number();
    let name = format!("/proc/self/fd/{free}/../prog");
    assert_eq!(
        native_execve(&cwd, name.as_bytes(), &[]),
        Err(libc::ENOENT),
        "natively"
    );
    assert_eq!(
        resolve_guest_exec_image(&state, name.into_bytes(), &mut None).unwrap_err(),
        negative_errno(libc::ENOENT)
    );
    let planted = exec_interpreter_plant(&std::fs::File::open(root.0.join("held")).unwrap());
    for name in [
        format!("/proc/self/fd/{}/../prog", planted.as_raw_fd()),
        format!("/dev/fd/{}/../prog", planted.as_raw_fd()),
    ] {
        assert_eq!(
            resolve_guest_exec_image(&state, name.clone().into_bytes(), &mut None).unwrap_err(),
            negative_errno(libc::ENOENT),
            "{name}: a number the guest does not hold"
        );
    }
}

/// Slashes after a `..` run do not make the rest absolute: `sub/..//prog`
/// is the working directory's prog, and a name that exists only at the root
/// is ENOENT there, as Linux answers.
#[test]
fn slashes_after_a_dot_dot_keep_the_rest_relative() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("sub")).unwrap();
    let program = root.0.join("prog");
    native_resolution_write_program(&program);
    let cwd = std::fs::File::open(&root.0).unwrap();
    for name in [
        "sub/..//prog".to_string(),
        "sub/..///./prog".to_string(),
        format!("{}/sub/..//prog", root.0.display()),
    ] {
        assert_eq!(
            native_execve(&cwd, name.as_bytes(), &[]),
            Ok(0),
            "{name} natively"
        );
        let resolved =
            resolve_guest_exec_image(&test_state(&root.0), name.clone().into_bytes(), &mut None)
                .unwrap_or_else(|errno| panic!("{name}: {errno}"));
        assert_eq!(
            exec_interpreter_identity(resolved.file.as_ref().unwrap().metadata().unwrap()),
            exec_interpreter_identity(std::fs::metadata(&program).unwrap()),
            "{name}"
        );
    }
    let at_root = if Path::new("/usr/bin/env").exists() {
        "usr/bin/env"
    } else {
        "bin/sh"
    };
    let name = format!("sub/..//{at_root}");
    assert_eq!(
        native_execve(&cwd, name.as_bytes(), &[]),
        Err(libc::ENOENT),
        "natively"
    );
    exec_interpreter_assert_refused(
        native_resolution_exec(test_state(&root.0), name.as_bytes(), &[]),
        libc::ENOENT,
        &name,
    );
}

/// From a working directory of /dev, `fd/<n>` is the guest's descriptor
/// link, as its absolute spelling /dev/fd/<n> is: a descriptor the guest
/// holds is ELOOP (the documented exact-link limit) and a number it does not
/// hold is ENOENT.
#[test]
fn a_relative_fd_link_from_dev_is_answered_by_the_guests_table() {
    let root = TestDir::new();
    let program = root.0.join("prog");
    native_resolution_write_program(&program);
    let mut state = test_state(Path::new("/dev"));
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let guest = guest_open(
        &mut memory,
        &mut state,
        program.to_str().unwrap(),
        libc::O_RDONLY,
    );
    assert!(guest >= 0, "open prog: {guest}");
    assert_eq!(
        resolve_guest_exec_image(&state, format!("fd/{guest}").into_bytes(), &mut None)
            .unwrap_err(),
        negative_errno(libc::ELOOP)
    );
    let dev = std::fs::File::open("/dev").unwrap();
    let free = exec_interpreter_free_number();
    assert_eq!(
        native_execve(&dev, format!("fd/{free}").as_bytes(), &[]),
        Err(libc::ENOENT),
        "natively"
    );
    let planted = exec_interpreter_plant(&std::fs::File::open(&program).unwrap());
    for number in [free, planted.as_raw_fd()] {
        assert_eq!(
            resolve_guest_exec_image(&state, format!("fd/{number}").into_bytes(), &mut None)
                .unwrap_err(),
            negative_errno(libc::ENOENT),
            "fd/{number}: a number the guest does not hold"
        );
    }
}

/// A relative name's first segment is classified by the working-directory
/// handle's current path, never by the recorded path, which a rename leaves
/// stale. Here the recorded path is /dev, so that classifying by it would
/// name the guest's descriptor table: `fd/<n>/prog` is still the working
/// directory's own file, as Linux runs it (native), and not the file below
/// the guest's descriptor <n>.
#[test]
fn a_relative_name_is_classified_by_the_working_directory_not_its_recorded_path() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("held")).unwrap();
    native_resolution_write_program(&root.0.join("held/prog"));
    std::fs::create_dir(root.0.join("cwd")).unwrap();
    let mut state = test_state(&root.0.join("cwd"));
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let held = root.0.join("held");
    let guest = guest_open(
        &mut memory,
        &mut state,
        held.to_str().unwrap(),
        libc::O_RDONLY,
    );
    assert!(guest >= 0, "open held: {guest}");
    std::fs::create_dir_all(root.0.join(format!("cwd/fd/{guest}"))).unwrap();
    let program = root.0.join(format!("cwd/fd/{guest}/prog"));
    native_resolution_write_program(&program);
    state.fs_context.cwd = std::path::PathBuf::from("/dev");
    let name = format!("fd/{guest}/prog");
    let cwd = std::fs::File::open(root.0.join("cwd")).unwrap();
    assert_eq!(
        native_execve(&cwd, name.as_bytes(), &[]),
        Ok(0),
        "{name} natively"
    );
    let ours = resolve_guest_exec_image(&state, name.clone().into_bytes(), &mut None).unwrap();
    assert_eq!(
        exec_interpreter_identity(ours.file.as_ref().unwrap().metadata().unwrap()),
        exec_interpreter_identity(std::fs::metadata(&program).unwrap()),
        "{name}"
    );
}

/// A trailing slash, or a trailing `/.`, asks for a directory, as Linux reads
/// it: below a descriptor the guest holds, `/proc/self/fd/<n>/` is ENOTDIR
/// for a regular file and EACCES for a directory, and
/// `/proc/self/fd/<n>/prog/` is ENOTDIR, each as Linux answers for a
/// descriptor of the same kind (native), and the same with `/.`.
/// `/proc/self/exe/` and `/proc/self/exe/.` are not the caller's exe link:
/// they are refused, and the caller's own image is not run.
#[test]
fn a_trailing_slash_after_a_link_asks_for_a_directory() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("lib")).unwrap();
    native_resolution_write_program(&root.0.join("lib/prog"));
    // A state holding lib/prog and lib, with the guest's numbers for them.
    let holding = || {
        let mut state = native_resolution_state_with_own_image(&root.0);
        let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
        let file = guest_open(&mut memory, &mut state, "lib/prog", libc::O_RDONLY);
        assert!(file >= 0, "open lib/prog: {file}");
        let directory = guest_open(&mut memory, &mut state, "lib", libc::O_RDONLY);
        assert!(directory >= 0, "open lib: {directory}");
        (state, file, directory)
    };
    let native_file = std::fs::File::open(root.0.join("lib/prog")).unwrap();
    let native_directory = std::fs::File::open(root.0.join("lib")).unwrap();
    let cwd = std::fs::File::open(&root.0).unwrap();
    let (_, file, directory) = holding();
    let rows = ["/", "/."].into_iter().flat_map(|tail| {
        [
            (
                format!("/proc/self/fd/{file}{tail}"),
                format!("/proc/self/fd/{}{tail}", native_file.as_raw_fd()),
            ),
            (
                format!("/proc/self/fd/{directory}{tail}"),
                format!("/proc/self/fd/{}{tail}", native_directory.as_raw_fd()),
            ),
            (
                format!("/proc/self/fd/{directory}/prog{tail}"),
                format!("/proc/self/fd/{}/prog{tail}", native_directory.as_raw_fd()),
            ),
        ]
    });
    for (name, native_name) in rows {
        let Err(errno) = native_execve(&cwd, native_name.as_bytes(), &[]) else {
            panic!("{native_name} ran natively");
        };
        let (state, _, _) = holding();
        exec_interpreter_assert_refused(
            native_resolution_exec(state, name.as_bytes(), &[]),
            errno,
            &name,
        );
    }
    for name in ["/proc/self/exe/", "/proc/self/exe/."] {
        exec_interpreter_assert_refused(
            native_resolution_exec(
                native_resolution_state_with_own_image(&root.0),
                name.as_bytes(),
                &[],
            ),
            libc::ELOOP,
            name,
        );
    }
}

/// Repeated slashes are one and a `.` component names nothing, as in any
/// Linux path: `//proc/self/exe`, `///proc/thread-self/exe`,
/// `/proc//self/exe` and `/proc/./self/exe` are the caller's exe link and
/// run its own image. (Not exec'd natively here, which would run this test
/// binary.)
#[test]
fn repeated_slashes_and_dot_components_in_the_exe_link_name_nothing() {
    let root = TestDir::new();
    let state = native_resolution_state_with_own_image(&root.0);
    for name in [
        "//proc/self/exe",
        "///proc/thread-self/exe",
        "/proc//self/exe",
        "/proc/./self/exe",
    ] {
        let resolved =
            resolve_guest_exec_image(&state, name.as_bytes().to_vec(), &mut None).unwrap();
        assert!(
            Arc::ptr_eq(
                resolved.file.as_ref().unwrap(),
                state.executable_file.as_ref().unwrap()
            ),
            "{name}"
        );
        assert_eq!(resolved.image, b"own image", "{name}");
    }
}

/// A directory whose path is longer than a page has no path for
/// /proc/self/fd to read (ENAMETOOLONG), but Linux still climbs from it: a
/// `..` from such a working directory, and from such a directory named by a
/// descriptor the guest holds, runs the program in its parent (native).
#[test]
fn a_climb_from_a_directory_deeper_than_a_page_matches_linux() {
    let root = TestDir::new();
    // A parent of about 3900 bytes, so that it and its prog are readable and
    // its 250-byte child is not.
    let mut parent = root.0.clone();
    while parent.as_os_str().len() < 3700 {
        parent.push("p".repeat(200));
    }
    parent.push("q".repeat(3900 - parent.as_os_str().len() - 1));
    std::fs::create_dir_all(&parent).unwrap();
    let program = parent.join("prog");
    native_resolution_write_program(&program);
    let name = "d".repeat(250);
    let parent_file = std::fs::File::open(&parent).unwrap();
    let deep_name = CString::new(name.clone()).unwrap();
    // SAFETY: a live descriptor and a NUL-terminated name; the result is owned.
    let deep = unsafe {
        assert_eq!(
            libc::mkdirat(parent_file.as_raw_fd(), deep_name.as_ptr(), 0o755),
            0,
            "mkdirat"
        );
        let fd = libc::openat(
            parent_file.as_raw_fd(),
            deep_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        );
        assert!(
            fd >= 0,
            "open the deep directory: {}",
            std::io::Error::last_os_error()
        );
        <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd)
    };
    assert_eq!(
        std::fs::read_link(format!("/proc/self/fd/{}", deep.as_raw_fd()))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENAMETOOLONG),
        "the deep directory's path is longer than a page"
    );
    let identity = exec_interpreter_identity(std::fs::metadata(&program).unwrap());

    assert_eq!(
        native_execve(&deep, b"../prog", &[]),
        Ok(0),
        "../prog natively"
    );
    let mut state = test_state(&parent);
    state.fs_context.cwd_fd = deep.try_clone().unwrap();
    let ours = resolve_guest_exec_image(&state, b"../prog".to_vec(), &mut None).unwrap();
    assert_eq!(
        exec_interpreter_identity(ours.file.as_ref().unwrap().metadata().unwrap()),
        identity,
        "../prog"
    );

    let native_name = format!("/proc/self/fd/{}/../prog", deep.as_raw_fd());
    assert_eq!(
        native_execve(&parent_file, native_name.as_bytes(), &[]),
        Ok(0),
        "{native_name} natively"
    );
    let mut state = test_state(&parent);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let held = guest_open(&mut memory, &mut state, &name, libc::O_RDONLY);
    assert!(held >= 0, "open the deep directory: {held}");
    let ours = resolve_guest_exec_image(
        &state,
        format!("/proc/self/fd/{held}/../prog").into_bytes(),
        &mut None,
    )
    .unwrap();
    assert_eq!(
        exec_interpreter_identity(ours.file.as_ref().unwrap().metadata().unwrap()),
        identity,
        "/proc/self/fd/<n>/../prog"
    );
}

/// A program whose own path is longer than a page cannot be named for its
/// load (the loader reads the opened file's /proc/self/fd entry, which is
/// ENAMETOOLONG), so its exec is refused with ENOEXEC before anything is
/// published, from a working directory that deep and through a descriptor
/// the guest holds on it. Linux runs it (native): a documented limit, which
/// fails before the point of no return rather than after it.
#[test]
fn a_program_deeper_than_a_page_is_refused_before_anything_is_published() {
    let root = TestDir::new();
    let mut parent = root.0.clone();
    while parent.as_os_str().len() < 3700 {
        parent.push("p".repeat(200));
    }
    parent.push("q".repeat(3900 - parent.as_os_str().len() - 1));
    std::fs::create_dir_all(&parent).unwrap();
    let name = "d".repeat(250);
    let parent_file = std::fs::File::open(&parent).unwrap();
    let deep_name = CString::new(name.clone()).unwrap();
    // SAFETY: live descriptors and NUL-terminated names; the results are owned.
    let (deep, mut program) = unsafe {
        assert_eq!(
            libc::mkdirat(parent_file.as_raw_fd(), deep_name.as_ptr(), 0o755),
            0,
            "mkdirat"
        );
        let fd = libc::openat(
            parent_file.as_raw_fd(),
            deep_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        );
        assert!(
            fd >= 0,
            "open the deep directory: {}",
            std::io::Error::last_os_error()
        );
        let program = libc::openat(
            fd,
            c"prog".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o700,
        );
        assert!(
            program >= 0,
            "create the deep program: {}",
            std::io::Error::last_os_error()
        );
        (
            <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd),
            <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(program),
        )
    };
    std::io::Write::write_all(
        &mut program,
        &crate::elf::minimal_test_elf(&EXEC_INTERPRETER_EXIT_ZERO),
    )
    .unwrap();
    drop(program);
    assert_eq!(
        native_execve(&deep, b"./prog", &[]),
        Ok(0),
        "./prog natively"
    );

    let mut state = test_state(&parent);
    state.fs_context.cwd_fd = deep.try_clone().unwrap();
    exec_interpreter_assert_refused(
        native_resolution_exec(state, b"./prog", &[]),
        libc::ENOEXEC,
        "./prog",
    );

    let mut state = test_state(&parent);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let held = guest_open(&mut memory, &mut state, &name, libc::O_RDONLY);
    assert!(held >= 0, "open the deep directory: {held}");
    let spelling = format!("/proc/self/fd/{held}/prog");
    exec_interpreter_assert_refused(
        native_resolution_exec(state, spelling.as_bytes(), &[]),
        libc::ENOEXEC,
        &spelling,
    );
}

/// An exec through an ordinary symbolic link into /proc/self/fd, or of
/// /dev/stdin, is refused (ELOOP or ENOENT) with nothing published and no
/// typed refusal. Linux follows the guest's descriptor: a documented limit.
#[test]
fn an_exec_through_a_symlink_into_the_descriptor_table_is_refused() {
    let root = TestDir::new();
    native_resolution_write_program(&root.0.join("prog"));
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let held = guest_open(&mut memory, &mut state, "prog", libc::O_RDONLY);
    assert!(held >= 0, "open prog: {held}");
    std::os::unix::fs::symlink(format!("/proc/self/fd/{held}"), root.0.join("link")).unwrap();
    for name in ["link", "/dev/stdin"] {
        let mut state = test_state(&root.0);
        assert_eq!(
            guest_open(&mut memory, &mut state, "prog", libc::O_RDONLY),
            held
        );
        let outcome = native_resolution_exec(state, name.as_bytes(), &[]);
        assert!(
            outcome.result == Some(negative_errno(libc::ELOOP))
                || outcome.result == Some(negative_errno(libc::ENOENT)),
            "{name}: {:?}",
            outcome.result
        );
        assert_eq!(outcome.refusal, None, "{name}");
        assert!(outcome.action.is_none(), "{name}: an exec was published");
    }
}

/// From a working directory that has been removed, a name below it is
/// ENOENT and `..` still leads to the parent, as Linux answers (native).
#[test]
fn an_exec_from_a_removed_working_directory_matches_linux() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("gone")).unwrap();
    let program = root.0.join("prog");
    native_resolution_write_program(&program);
    let state = test_state(&root.0.join("gone"));
    let cwd = std::fs::File::open(root.0.join("gone")).unwrap();
    std::fs::remove_dir(root.0.join("gone")).unwrap();
    assert_eq!(
        native_execve(&cwd, b"prog", &[]),
        Err(libc::ENOENT),
        "prog natively"
    );
    assert_eq!(
        resolve_guest_exec_image(&state, b"prog".to_vec(), &mut None).unwrap_err(),
        negative_errno(libc::ENOENT)
    );
    let native = native_execve(&cwd, b"../prog", &[]);
    let ours = resolve_guest_exec_image(&state, b"../prog".to_vec(), &mut None);
    match native {
        Ok(code) => {
            assert_eq!(code, 0, "../prog natively");
            assert_eq!(
                exec_interpreter_identity(ours.unwrap().file.as_ref().unwrap().metadata().unwrap()),
                exec_interpreter_identity(std::fs::metadata(&program).unwrap()),
                "../prog"
            );
        }
        Err(errno) => assert_eq!(ours.unwrap_err(), negative_errno(errno), "../prog"),
    }
}

/// An exec path is looked up only with openat2. A host that refuses that
/// call (here a seccomp filter answering ENOSYS, as a kernel or sandbox
/// without it does) gets the exec refused by name, never looked up another
/// way. The filter binds an isolated child of this test binary.
#[test]
fn an_exec_whose_lookup_the_host_refuses_is_refused_by_name() {
    const TEST: &str = "an_exec_whose_lookup_the_host_refuses_is_refused_by_name";
    if !host_resources_is_child(TEST) {
        return host_resources_run_isolated(TEST);
    }
    native_resolution_assert_lookup_refused(libc::ENOSYS);
}

/// The same for a host that refuses openat2 with EPERM, as a seccomp
/// sandbox may.
#[test]
fn an_exec_whose_lookup_the_host_refuses_with_eperm_is_refused_by_name() {
    const TEST: &str = "an_exec_whose_lookup_the_host_refuses_with_eperm_is_refused_by_name";
    if !host_resources_is_child(TEST) {
        return host_resources_run_isolated(TEST);
    }
    native_resolution_assert_lookup_refused(libc::EPERM);
}

/// Asserts that, with openat2 failing with `errno`, an exec by an absolute
/// name, by a name with `..`, by a bare name and by a name below a
/// descriptor the guest holds is each refused by name.
fn native_resolution_assert_lookup_refused(errno: i32) {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("sub")).unwrap();
    native_resolution_write_program(&root.0.join("prog"));
    native_resolution_write_program(&root.0.join("sub/prog"));
    let mut held_state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let held = guest_open(&mut memory, &mut held_state, "sub", libc::O_RDONLY);
    assert!(held >= 0, "open sub: {held}");
    let mut cases = vec![
        (
            root.0.join("prog").display().to_string(),
            test_state(&root.0),
        ),
        (
            format!("{}/sub/../prog", root.0.display()),
            test_state(&root.0),
        ),
        ("prog".to_string(), test_state(&root.0)),
    ];
    cases.push((format!("/proc/self/fd/{held}/prog"), held_state));
    native_resolution_refuse_openat2(errno);
    for (name, state) in cases {
        let name = &name;
        let outcome = native_resolution_exec(state, name.as_bytes(), &[]);
        assert_eq!(
            outcome.result,
            Some(negative_errno(libc::EOPNOTSUPP)),
            "{name}"
        );
        let refusal = outcome.refusal.expect("a typed refusal");
        assert_eq!(
            refusal.operation,
            reverie::UnsupportedOperation::Exec,
            "{name}"
        );
        assert_eq!(refusal.diagnostic, EXEC_PATH_LOOKUP_REFUSAL, "{name}");
        assert!(outcome.action.is_none(), "{name}: an exec was published");
    }
}

/// Installs, on this thread, a seccomp filter under which openat2 fails with
/// `errno` and every other call is allowed.
fn native_resolution_refuse_openat2(errno: i32) {
    const LOAD_NR: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JUMP_EQ: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RETURN: u16 = 0x06; // BPF_RET | BPF_K
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    let filter = [
        libc::sock_filter {
            code: LOAD_NR,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: JUMP_EQ,
            jt: 0,
            jf: 1,
            k: libc::SYS_openat2 as u32,
        },
        libc::sock_filter {
            code: RETURN,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | errno as u32,
        },
        libc::sock_filter {
            code: RETURN,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: prctl reads `program`, which outlives the call; the filter only
    // narrows this thread's own syscalls.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
            0,
            "seccomp: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// An interpreter spelled with `..` is looked up as Linux walks it: the
/// parent of the directory reached. Through an existing directory it is the
/// file there; after a missing name it is ENOENT, where a lexical fold would
/// find the file.
#[test]
fn an_interpreter_spelled_with_dot_dot_is_looked_up_physically() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("sub")).unwrap();
    let interpreter = root.0.join("interpreter");
    exec_interpreter_write(&interpreter);
    let program = root.0.join("program");
    exec_interpreter_write_program(
        &program,
        &format!("{}/sub/../interpreter", root.0.display()),
    );
    let native = std::process::Command::new(&program).status().unwrap();
    assert_eq!(native.code(), Some(0), "natively: {native:?}");
    let staged = exec_interpreter_staged(
        exec_interpreter_exec(test_state(&root.0), program.to_str().unwrap()),
        "interpreter through sub/..",
    );
    assert_eq!(
        staged,
        exec_interpreter_identity(std::fs::metadata(&interpreter).unwrap())
    );

    let missing = root.0.join("missing-program");
    exec_interpreter_write_program(
        &missing,
        &format!("{}/missing/../interpreter", root.0.display()),
    );
    let native = std::process::Command::new(&missing).status();
    assert_eq!(
        native.map_err(|error| error.raw_os_error()).err(),
        Some(Some(libc::ENOENT)),
        "natively"
    );
    exec_interpreter_assert_refused(
        exec_interpreter_exec(test_state(&root.0), missing.to_str().unwrap()),
        libc::ENOENT,
        "interpreter through missing/..",
    );
}
