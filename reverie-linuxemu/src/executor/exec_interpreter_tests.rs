/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// An exec resolves the program interpreter its new image names (`PT_INTERP`)
// in the guest's view, as it resolves the program, before either load
// (`read_exec_interpreter`); the loads map the file it staged and open no
// interpreter path themselves. The supervisor plants a file at a descriptor
// number of at least 4000 that the guest does not hold: no spelling of that
// number reaches it.

/// mov eax, 60 (exit); xor edi, edi; syscall: an interpreter that exits 0.
const EXEC_INTERPRETER_EXIT_ZERO: [u8; 9] = [0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];

/// The supervisor's own duplicate of `file`, at a descriptor number of at
/// least 4000 the guest does not hold.
fn exec_interpreter_plant(file: &std::fs::File) -> std::os::fd::OwnedFd {
    // SAFETY: fcntl duplicates the descriptor `file` owns; it returns a new descriptor or -1.
    let planted = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4000) };
    assert!(planted >= 4000, "planting supervisor descriptor: {planted}");
    // SAFETY: fcntl just returned this new descriptor (checked above), and nothing else owns it.
    unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(planted) }
}

/// A descriptor number of at least 4000 that this process does not hold.
fn exec_interpreter_free_number() -> i32 {
    (4321..8192)
        // SAFETY: F_GETFD reads only the descriptor's flags; -1 means it is not open.
        .find(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1)
        .expect("a free descriptor number above 4000")
}

/// The device and inode of the file at `path`, or of the open `file`.
fn exec_interpreter_identity(metadata: std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

/// Writes a minimal interpreter that exits 0 at `path`, mode 0700.
fn exec_interpreter_write(path: &Path) {
    host_resources_write_executable(
        path,
        &crate::elf::minimal_test_interpreter(&EXEC_INTERPRETER_EXIT_ZERO, 2),
    );
}

/// Writes at `path` a program, mode 0700, whose `PT_INTERP` names
/// `interpreter`.
fn exec_interpreter_write_program(path: &Path, interpreter: &str) {
    let mut named = interpreter.as_bytes().to_vec();
    named.push(0);
    host_resources_write_executable(
        path,
        &crate::elf::minimal_test_elf_with_interpreter(&[0x0f, 0x0b], &named),
    );
}

/// What an exec from an executor over a state returned: its result, the
/// typed refusal it recorded and the exec it published.
struct ExecInterpreterOutcome {
    result: Option<i64>,
    refusal: Option<reverie::UnsupportedRefusal>,
    action: Option<ProcessAction>,
}

/// Execs the guest path `program` from an executor over `state`.
fn exec_interpreter_exec(state: LoadedStaticElf, program: &str) -> ExecInterpreterOutcome {
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let request = host_resources_exec_request(&mut memory, program.as_bytes());
    let mut executor = ElfExecutor::new(state, false);
    let result = executor.execute_process_action(&request, &memory);
    ExecInterpreterOutcome {
        result,
        refusal: executor.take_unsupported_refusal(),
        action: executor.take_process_action(),
    }
}

/// Asserts that `outcome` refused the exec with `errno`: no typed refusal,
/// nothing published.
fn exec_interpreter_assert_refused(outcome: ExecInterpreterOutcome, errno: i32, what: &str) {
    assert_eq!(
        outcome.result,
        Some(negative_errno(errno)),
        "{what}: refusal {:?}",
        outcome.refusal
    );
    assert_eq!(outcome.refusal, None, "{what}");
    assert!(outcome.action.is_none(), "{what}: an exec was published");
}

/// The identity of the interpreter `outcome`'s published exec staged.
fn exec_interpreter_staged(outcome: ExecInterpreterOutcome, what: &str) -> (u64, u64) {
    assert_eq!(
        outcome.result,
        Some(0),
        "{what}: refusal {:?}",
        outcome.refusal
    );
    assert_eq!(outcome.refusal, None, "{what}");
    let Some(ProcessAction::Exec {
        interpreter: Some(interpreter),
        ..
    }) = outcome.action
    else {
        panic!("{what}: no exec with a staged interpreter was published");
    };
    exec_interpreter_identity(interpreter.file().metadata().unwrap())
}

/// The inodes of the files whose mappings `memory` holds.
fn exec_interpreter_mapped_inodes(memory: &GuestMemory) -> Vec<u64> {
    memory
        .mapping_identities_in(memory.guest_base(), memory.len() as u64)
        .iter()
        .filter_map(|identity| match identity.downcast_ref::<super::mapping_list::MappedObject>() {
            Some(super::mapping_list::MappedObject::File { raw_inode, .. }) => Some(*raw_inode),
            _ => None,
        })
        .collect()
}

/// Permission answers below depend on the effective uid: logged, so a run
/// as root is visible in the test output.
#[test]
fn exec_interpreter_tests_log_the_effective_uid() {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    eprintln!("exec_interpreter_tests: effective uid {euid}");
}

/// A program whose interpreter exits 0, named by its absolute path: native
/// Linux runs it, and the exec stages exactly that file.
#[test]
fn an_interpreter_named_by_an_absolute_path_is_the_file_staged() {
    let root = TestDir::new();
    let interpreter = root.0.join("interpreter");
    exec_interpreter_write(&interpreter);
    let program = root.0.join("program");
    exec_interpreter_write_program(&program, interpreter.to_str().unwrap());
    let native = std::process::Command::new(&program).status().unwrap();
    assert_eq!(native.code(), Some(0), "natively: {native:?}");

    let staged = exec_interpreter_staged(
        exec_interpreter_exec(test_state(&root.0), program.to_str().unwrap()),
        "absolute interpreter",
    );
    assert_eq!(
        staged,
        exec_interpreter_identity(std::fs::metadata(&interpreter).unwrap())
    );
}

/// A relative `PT_INTERP` resolves against the guest's working directory,
/// as Linux opens it (fs/binfmt_elf.c `load_elf_binary` calls `open_exec`),
/// not against the supervisor's.
#[test]
fn a_relative_interpreter_resolves_against_the_guest_working_directory() {
    let root = TestDir::new();
    let name = format!("relative-interpreter-{}", std::process::id());
    assert!(
        !Path::new(&name).exists(),
        "{name} exists in the supervisor's working directory"
    );
    exec_interpreter_write(&root.0.join(&name));
    let program = root.0.join("program");
    exec_interpreter_write_program(&program, &name);
    let native = std::process::Command::new(&program)
        .current_dir(&root.0)
        .status()
        .unwrap();
    assert_eq!(native.code(), Some(0), "natively: {native:?}");

    let staged = exec_interpreter_staged(
        exec_interpreter_exec(test_state(&root.0), program.to_str().unwrap()),
        "relative interpreter",
    );
    assert_eq!(
        staged,
        exec_interpreter_identity(std::fs::metadata(root.0.join(&name)).unwrap())
    );
}

/// An interpreter below a directory the guest holds (`/proc/self/fd/<D>/x`)
/// is the file below the guest's descriptor, at the guest's own low number
/// and at a number of at least 4000 the supervisor does not hold.
#[test]
fn an_interpreter_below_a_held_directory_descriptor_is_the_guests_file() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("lib")).unwrap();
    let interpreter = root.0.join("lib/interpreter");
    exec_interpreter_write(&interpreter);
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let low = guest_open(&mut memory, &mut state, "lib", libc::O_RDONLY);
    assert!(low >= 0, "open lib: {low}");
    let high = exec_interpreter_free_number();
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_dup2,
            [low as u64, high as u64, 0, 0, 0, 0],
        ),
        i64::from(high),
        "dup2 onto {high}"
    );
    // SAFETY: F_GETFD reads only the descriptor's flags; -1 means it is not open.
    assert_eq!(
        unsafe { libc::fcntl(high, libc::F_GETFD) },
        -1,
        "the supervisor holds {high}"
    );
    let mut executor = ElfExecutor::new(state, false);
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    for directory in [low, i64::from(high)] {
        let program = root.0.join(format!("program-{directory}"));
        exec_interpreter_write_program(&program, &format!("/proc/self/fd/{directory}/interpreter"));
        let request = host_resources_exec_request(&mut memory, program.as_os_str().as_bytes());
        let result = executor.execute_process_action(&request, &memory);
        let staged = exec_interpreter_staged(
            ExecInterpreterOutcome {
                result,
                refusal: executor.take_unsupported_refusal(),
                action: executor.take_process_action(),
            },
            &format!("interpreter below held directory {directory}"),
        );
        assert_eq!(
            staged,
            exec_interpreter_identity(std::fs::metadata(&interpreter).unwrap())
        );
    }
}

/// An interpreter named by an fd link to a descriptor only the supervisor
/// holds is ENOENT, as Linux answers for a descriptor that is not open
/// (fs/proc/fd.c `proc_lookupfd_common`), in every spelling of the link: the
/// supervisor's file is never staged.
#[test]
fn an_interpreter_named_by_an_unheld_descriptor_link_is_enoent() {
    let root = TestDir::new();
    let secret = root.0.join("secret-interpreter");
    exec_interpreter_write(&secret);
    let planted = exec_interpreter_plant(&std::fs::File::open(&secret).unwrap());
    let s = planted.as_raw_fd();
    let pid = std::process::id();
    // SAFETY: gettid has no preconditions.
    let tid = unsafe { libc::gettid() };
    let spellings = [
        format!("/proc/self/fd/{s}"),
        format!("/dev/fd/{s}"),
        format!("/proc/thread-self/fd/{s}"),
        format!("/proc/{pid}/fd/{s}"),
        format!("/proc/self/task/{tid}/fd/{s}"),
        format!("/proc/1/fd/{s}"),
        format!("/proc/self/task/1/fd/{s}"),
    ];
    for (index, spelling) in spellings.iter().enumerate() {
        let state = test_state(&root.0);
        assert_eq!(
            read_exec_interpreter(&state, spelling, &mut None).err(),
            Some(negative_errno(libc::ENOENT)),
            "read interpreter {spelling}"
        );
        let program = root.0.join(format!("program-{index}"));
        exec_interpreter_write_program(&program, spelling);
        exec_interpreter_assert_refused(
            exec_interpreter_exec(state, program.to_str().unwrap()),
            libc::ENOENT,
            &format!("exec with interpreter {spelling}"),
        );
    }
}

/// An interpreter named by the exact fd link of a descriptor the guest holds
/// is ELOOP, as a program named so is (`read_executable_file`): the link is
/// one this exec does not follow, and Linux answers ELOOP for a magic link
/// it will not follow (fs/namei.c `nd_jump_link`). The guest's descriptor is
/// tried at its own low number and at a number of at least 4000 the
/// supervisor does not hold, so the answer comes from the guest's table.
#[test]
fn an_interpreter_named_by_a_held_descriptor_link_is_eloop() {
    let root = TestDir::new();
    let interpreter = root.0.join("interpreter");
    exec_interpreter_write(&interpreter);
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let low = guest_open(&mut memory, &mut executor.state, "interpreter", libc::O_RDONLY);
    assert!(low >= 0, "open interpreter: {low}");
    let high = exec_interpreter_free_number();
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut executor.state,
            libc::SYS_dup2,
            [low as u64, high as u64, 0, 0, 0, 0],
        ),
        i64::from(high),
        "dup2 onto {high}"
    );
    // SAFETY: F_GETFD reads only the descriptor's flags; -1 means it is not open.
    assert_eq!(
        unsafe { libc::fcntl(high, libc::F_GETFD) },
        -1,
        "the supervisor holds {high}"
    );
    for (index, fd) in [low, i64::from(high)].into_iter().enumerate() {
        for (form, spelling) in [format!("/proc/self/fd/{fd}"), format!("/dev/fd/{fd}")]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                read_exec_interpreter(&executor.state, &spelling, &mut None).err(),
                Some(negative_errno(libc::ELOOP)),
                "read interpreter {spelling}"
            );
            let program = root.0.join(format!("program-{index}-{form}"));
            exec_interpreter_write_program(&program, &spelling);
            let request =
                host_resources_exec_request(&mut memory, program.as_os_str().as_bytes());
            let result = executor.execute_process_action(&request, &memory);
            exec_interpreter_assert_refused(
                ExecInterpreterOutcome {
                    result,
                    refusal: executor.take_unsupported_refusal(),
                    action: executor.take_process_action(),
                },
                libc::ELOOP,
                &format!("exec with interpreter {spelling}"),
            );
        }
    }
}

/// Spellings that reach a descriptor link through a symlink (absolute or
/// relative, `/dev/stdin`), or that name `/proc/self/exe`, `/proc/self/root`
/// or `/proc/self/cwd`, are refused (ELOOP or ENOENT), and no file is staged.
/// Linux follows them; this is a documented limit, as for a program named so.
#[test]
fn an_interpreter_reaching_an_fd_link_indirectly_is_refused() {
    let root = TestDir::new();
    let secret = root.0.join("secret-interpreter");
    exec_interpreter_write(&secret);
    let planted = exec_interpreter_plant(&std::fs::File::open(&secret).unwrap());
    let free = exec_interpreter_free_number();
    std::os::unix::fs::symlink(
        format!("/proc/self/fd/{}", planted.as_raw_fd()),
        root.0.join("link-to-plant"),
    )
    .unwrap();
    std::os::unix::fs::symlink(format!("/proc/self/fd/{free}"), root.0.join("link-to-free"))
        .unwrap();
    // SAFETY: F_GETFD reads only the descriptor's flags; -1 means it is not open.
    let stdin_errno = if unsafe { libc::fcntl(0, libc::F_GETFD) } != -1 {
        libc::ELOOP
    } else {
        libc::ENOENT
    };
    let below_root = format!("/proc/self/root{}", secret.display());
    let absolute_plant = root.0.join("link-to-plant");
    let absolute_free = root.0.join("link-to-free");
    let cases = [
        (absolute_plant.to_str().unwrap(), libc::ELOOP),
        ("link-to-plant", libc::ELOOP),
        (absolute_free.to_str().unwrap(), libc::ENOENT),
        ("/dev/stdin", stdin_errno),
        ("/proc/self/exe", libc::ELOOP),
        (below_root.as_str(), libc::ELOOP),
        ("/proc/self/cwd/secret-interpreter", libc::ELOOP),
    ];
    for (index, (spelling, errno)) in cases.into_iter().enumerate() {
        let program = root.0.join(format!("program-{index}"));
        exec_interpreter_write_program(&program, spelling);
        exec_interpreter_assert_refused(
            exec_interpreter_exec(test_state(&root.0), program.to_str().unwrap()),
            errno,
            &format!("exec with interpreter {spelling}"),
        );
    }
}

/// An interpreter reached through a chain of ordinary symlinks is the file
/// at its end, as on Linux; a symlink loop is ELOOP, as on Linux.
#[test]
fn an_interpreter_symlink_chain_resolves_and_a_loop_is_eloop() {
    let root = TestDir::new();
    let interpreter = root.0.join("interpreter");
    exec_interpreter_write(&interpreter);
    std::os::unix::fs::symlink(&interpreter, root.0.join("second")).unwrap();
    std::os::unix::fs::symlink("second", root.0.join("first")).unwrap();
    std::os::unix::fs::symlink("loop-b", root.0.join("loop-a")).unwrap();
    std::os::unix::fs::symlink("loop-a", root.0.join("loop-b")).unwrap();

    let chain = root.0.join("program-chain");
    exec_interpreter_write_program(&chain, root.0.join("first").to_str().unwrap());
    let native = std::process::Command::new(&chain).status().unwrap();
    assert_eq!(native.code(), Some(0), "chain natively: {native:?}");
    assert_eq!(
        exec_interpreter_staged(
            exec_interpreter_exec(test_state(&root.0), chain.to_str().unwrap()),
            "interpreter through a symlink chain",
        ),
        exec_interpreter_identity(std::fs::metadata(&interpreter).unwrap())
    );

    let looping = root.0.join("program-loop");
    exec_interpreter_write_program(&looping, root.0.join("loop-a").to_str().unwrap());
    let native = std::process::Command::new(&looping)
        .status()
        .expect_err("Linux refuses the exec");
    assert_eq!(native.raw_os_error(), Some(libc::ELOOP), "loop natively: {native}");
    exec_interpreter_assert_refused(
        exec_interpreter_exec(test_state(&root.0), looping.to_str().unwrap()),
        libc::ELOOP,
        "interpreter through a symlink loop",
    );
}

/// An interpreter below a directory descriptor only the supervisor holds,
/// at a number of at least 4000, is ENOENT, as Linux answers for a
/// descriptor that is not open, and the supervisor's file is never staged.
#[test]
fn an_interpreter_below_an_unheld_directory_descriptor_is_enoent() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("lib")).unwrap();
    exec_interpreter_write(&root.0.join("lib/interpreter"));
    let planted = exec_interpreter_plant(&std::fs::File::open(root.0.join("lib")).unwrap());
    let state = test_state(&root.0);
    assert!(host_fd(&state, planted.as_raw_fd()).is_none());
    let program = root.0.join("program");
    exec_interpreter_write_program(
        &program,
        &format!("/proc/self/fd/{}/interpreter", planted.as_raw_fd()),
    );
    exec_interpreter_assert_refused(
        exec_interpreter_exec(state, program.to_str().unwrap()),
        libc::ENOENT,
        "interpreter below a directory descriptor the guest does not hold",
    );
}

/// A FIFO named as the interpreter is EACCES at once, as on Linux, and is
/// never opened, so the exec cannot wait for a writer. The exec runs on a
/// thread with a bounded wait, so a regression fails instead of hanging.
#[test]
fn an_interpreter_that_is_a_fifo_is_eacces_and_never_opened() {
    let root = TestDir::new();
    let fifo = root.0.join("fifo");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: mkfifo reads only the NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o700) }, 0);
    let program = root.0.join("program");
    exec_interpreter_write_program(&program, fifo.to_str().unwrap());
    let native = std::process::Command::new(&program)
        .status()
        .expect_err("Linux refuses the exec");
    assert_eq!(native.raw_os_error(), Some(libc::EACCES), "natively: {native}");

    let (sender, receiver) = std::sync::mpsc::channel();
    let directory = root.0.clone();
    let program_name = program.to_str().unwrap().to_owned();
    let worker = std::thread::spawn(move || {
        let outcome = exec_interpreter_exec(test_state(&directory), &program_name);
        let _ = sender.send((outcome.result, outcome.refusal, outcome.action.is_none()));
    });
    match receiver.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok((result, refusal, unpublished)) => {
            worker.join().unwrap();
            assert_eq!(result, Some(negative_errno(libc::EACCES)), "{refusal:?}");
            assert_eq!(refusal, None);
            assert!(unpublished, "an exec with a FIFO interpreter was published");
        }
        Err(_) => {
            // The exec opened the FIFO and waits for a writer: be one, so the
            // worker ends, then fail.
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
            panic!("the exec opened its FIFO interpreter");
        }
    }
}

/// The interpreter is the one the image after every `#!` level names: a
/// script whose interpreter is a program naming an fd link only the
/// supervisor holds is ENOENT.
#[test]
fn the_interpreter_of_a_scripts_program_is_resolved_in_the_guests_view() {
    let root = TestDir::new();
    let secret = root.0.join("secret-interpreter");
    exec_interpreter_write(&secret);
    let planted = exec_interpreter_plant(&std::fs::File::open(&secret).unwrap());
    let program = root.0.join("program");
    exec_interpreter_write_program(&program, &format!("/proc/self/fd/{}", planted.as_raw_fd()));
    let script = root.0.join("script");
    host_resources_write_executable(
        &script,
        format!("#!{}\n", program.display()).as_bytes(),
    );
    exec_interpreter_assert_refused(
        exec_interpreter_exec(test_state(&root.0), script.to_str().unwrap()),
        libc::ENOENT,
        "script whose program names an unheld fd link",
    );
}

/// An interpreter Linux will not open as one is EACCES (fs/exec.c
/// `do_open_execat`): a directory, and a regular file no one may execute
/// (mode 0644, which root may not execute either). A file its owner may read
/// but only its group and others may execute (mode 0411) is checked against
/// Linux's own answer for this caller: EACCES for its owner, which a check
/// for any execute bit would miss, while root, who may execute a file with
/// any execute bit, runs it.
#[test]
fn an_interpreter_that_is_not_an_executable_regular_file_is_eacces() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("directory")).unwrap();
    let unexecutable = root.0.join("unexecutable");
    exec_interpreter_write(&unexecutable);
    std::fs::set_permissions(&unexecutable, std::fs::Permissions::from_mode(0o644)).unwrap();
    for (index, interpreter) in [root.0.join("directory"), unexecutable].iter().enumerate() {
        let program = root.0.join(format!("program-{index}"));
        exec_interpreter_write_program(&program, interpreter.to_str().unwrap());
        let native = std::process::Command::new(&program)
            .status()
            .expect_err("Linux refuses the exec");
        assert_eq!(
            native.raw_os_error(),
            Some(libc::EACCES),
            "{interpreter:?} natively: {native}"
        );
        exec_interpreter_assert_refused(
            exec_interpreter_exec(test_state(&root.0), program.to_str().unwrap()),
            libc::EACCES,
            &format!("exec with interpreter {interpreter:?}"),
        );
    }

    let others_only = root.0.join("others-only");
    exec_interpreter_write(&others_only);
    std::fs::set_permissions(&others_only, std::fs::Permissions::from_mode(0o411)).unwrap();
    let program = root.0.join("program-others-only");
    exec_interpreter_write_program(&program, others_only.to_str().unwrap());
    let outcome = exec_interpreter_exec(test_state(&root.0), program.to_str().unwrap());
    match std::process::Command::new(&program).status() {
        Err(native) => {
            assert_eq!(native.raw_os_error(), Some(libc::EACCES), "natively: {native}");
            exec_interpreter_assert_refused(outcome, libc::EACCES, "mode 0411 interpreter");
        }
        Ok(native) => {
            assert_eq!(native.code(), Some(0), "natively: {native:?}");
            exec_interpreter_staged(outcome, "mode 0411 interpreter");
        }
    }
}

/// An interpreter its caller may execute but not read (mode 0111) runs on
/// Linux, which opens it for execution only. Here it is EACCES, a documented
/// limit: the image is read through a descriptor opened for reading. Root
/// may read any file, so for root it runs here too and the case is skipped.
#[test]
fn an_execute_only_interpreter_is_eacces_where_linux_runs_it() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("SKIPPED: running as root, which may read a mode-0111 file");
        return;
    }
    let root = TestDir::new();
    let interpreter = root.0.join("execute-only");
    exec_interpreter_write(&interpreter);
    std::fs::set_permissions(&interpreter, std::fs::Permissions::from_mode(0o111)).unwrap();
    let program = root.0.join("program");
    exec_interpreter_write_program(&program, interpreter.to_str().unwrap());
    let native = std::process::Command::new(&program).status().unwrap();
    assert_eq!(native.code(), Some(0), "natively: {native:?}");
    exec_interpreter_assert_refused(
        exec_interpreter_exec(test_state(&root.0), program.to_str().unwrap()),
        libc::EACCES,
        "mode 0111 interpreter",
    );
}

/// An interpreter this loader cannot load is ENOEXEC: one larger than its
/// limit (`MAX_INTERPRETER_BYTES`), and an `ET_EXEC` one.
#[test]
fn an_interpreter_this_loader_cannot_load_is_enoexec() {
    let root = TestDir::new();
    let oversized = root.0.join("oversized");
    exec_interpreter_write(&oversized);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&oversized)
        .unwrap()
        .set_len(crate::elf::MAX_INTERPRETER_BYTES + 1)
        .unwrap();
    let static_program = root.0.join("static");
    host_resources_write_executable(
        &static_program,
        &crate::elf::minimal_test_elf(&EXEC_INTERPRETER_EXIT_ZERO),
    );
    for (index, interpreter) in [oversized, static_program].iter().enumerate() {
        let program = root.0.join(format!("program-{index}"));
        exec_interpreter_write_program(&program, interpreter.to_str().unwrap());
        exec_interpreter_assert_refused(
            exec_interpreter_exec(test_state(&root.0), program.to_str().unwrap()),
            libc::ENOEXEC,
            &format!("exec with interpreter {interpreter:?}"),
        );
    }
}

/// A PT_INTERP without its terminating NUL is ENOEXEC, as on Linux. One with
/// an embedded NUL is ENOEXEC too, a documented limit: Linux uses the bytes
/// before the NUL and runs that interpreter.
#[test]
fn a_pt_interp_without_its_nul_or_with_an_embedded_nul_is_enoexec() {
    let root = TestDir::new();
    let interpreter = root.0.join("interpreter");
    exec_interpreter_write(&interpreter);
    let path = interpreter.as_os_str().as_bytes();

    let unterminated = root.0.join("program-unterminated");
    host_resources_write_executable(
        &unterminated,
        &crate::elf::minimal_test_elf_with_interpreter(&[0x0f, 0x0b], path),
    );
    let native = std::process::Command::new(&unterminated)
        .status()
        .expect_err("Linux refuses the exec");
    assert_eq!(native.raw_os_error(), Some(libc::ENOEXEC), "natively: {native}");
    exec_interpreter_assert_refused(
        exec_interpreter_exec(test_state(&root.0), unterminated.to_str().unwrap()),
        libc::ENOEXEC,
        "PT_INTERP without its NUL",
    );

    let embedded = root.0.join("program-embedded");
    let named = [path, b"\0trailing\0"].concat();
    host_resources_write_executable(
        &embedded,
        &crate::elf::minimal_test_elf_with_interpreter(&[0x0f, 0x0b], &named),
    );
    let native = std::process::Command::new(&embedded).status().unwrap();
    assert_eq!(native.code(), Some(0), "natively: {native:?}");
    exec_interpreter_assert_refused(
        exec_interpreter_exec(test_state(&root.0), embedded.to_str().unwrap()),
        libc::ENOEXEC,
        "PT_INTERP with an embedded NUL",
    );
}

/// The load maps the interpreter the exec staged, once: a file renamed over
/// its path after staging is not mapped. A load with no staged interpreter
/// for an image that names one, or with one staged for another path or for
/// an image that names none, and a load of a `#!` script, are refused and
/// map nothing.
#[test]
fn a_load_maps_only_the_interpreter_the_exec_staged() {
    let root = TestDir::new();
    let interpreter = root.0.join("interpreter");
    exec_interpreter_write(&interpreter);
    let replacement = root.0.join("replacement");
    exec_interpreter_write(&replacement);
    let original_inode = std::fs::metadata(&interpreter).unwrap().ino();
    let replacement_inode = std::fs::metadata(&replacement).unwrap().ino();
    let path = interpreter.to_str().unwrap().to_owned();
    let mut named = path.as_bytes().to_vec();
    named.push(0);
    let image = crate::elf::minimal_test_elf_with_interpreter(&[0x0f, 0x0b], &named);
    let state = test_state(&root.0);
    let staged = read_exec_interpreter(&state, &path, &mut None).expect("staging the interpreter");
    std::fs::rename(&replacement, &interpreter).unwrap();
    let load = |memory: &mut GuestMemory, image: &[u8], staged| {
        crate::elf::load_static_elf_image_of(
            memory,
            image,
            None,
            staged,
            None,
            &["program"],
            &[],
            &root.0,
        )
    };

    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    load(&mut memory, &image, Some(&staged)).expect("loading the staged interpreter");
    let mapped = exec_interpreter_mapped_inodes(&memory);
    assert!(mapped.contains(&original_inode), "{mapped:?}");
    assert!(!mapped.contains(&replacement_inode), "{mapped:?}");

    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let error = load(&mut memory, &image, None).expect_err("no interpreter staged");
    assert!(
        matches!(&error, crate::Error::UnsupportedElf(message)
            if *message == format!("the interpreter {path:?} was not resolved for this exec")),
        "{error}"
    );
    assert_eq!(exec_interpreter_mapped_inodes(&memory), Vec::<u64>::new());

    let other = "/elsewhere/interpreter";
    let mut other_named = other.as_bytes().to_vec();
    other_named.push(0);
    let other_image = crate::elf::minimal_test_elf_with_interpreter(&[0x0f, 0x0b], &other_named);
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let error = load(&mut memory, &other_image, Some(&staged)).expect_err("staged for another path");
    assert!(
        matches!(&error, crate::Error::UnsupportedElf(message)
            if *message == format!("the interpreter {other:?} was not resolved for this exec")),
        "{error}"
    );
    assert_eq!(exec_interpreter_mapped_inodes(&memory), Vec::<u64>::new());

    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let error = load(
        &mut memory,
        &crate::elf::minimal_test_elf(&[0x0f, 0x0b]),
        Some(&staged),
    )
    .expect_err("staged for an image with no PT_INTERP");
    assert!(
        matches!(&error, crate::Error::UnsupportedElf(message)
            if message == "an interpreter was resolved for an image with no PT_INTERP"),
        "{error}"
    );
    assert_eq!(exec_interpreter_mapped_inodes(&memory), Vec::<u64>::new());
    // An exec resolves every `#!` level before it loads; a script handed to
    // an exec load is refused, never read by its interpreter's path.
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let script = format!("#!{path}\n");
    let error = load(&mut memory, script.as_bytes(), None).expect_err("a #! script");
    assert!(
        matches!(&error, crate::Error::UnsupportedElf(message)
            if message == "an exec load was handed a #! script"),
        "{error}"
    );
    assert_eq!(exec_interpreter_mapped_inodes(&memory), Vec::<u64>::new());
}
