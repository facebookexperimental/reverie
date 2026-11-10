// Tests of this backend's typed refusal of host resources (refusal.rs): an
// exec the host cannot give the memory or the descriptors it needs is refused
// by name, never answered with an errno the guest would take for one of its
// own.

/// A minimal valid static x86-64 executable: one PT_LOAD of a page at
/// 0x20_0000 whose entry point holds `ud2`.
fn host_resources_test_image() -> Vec<u8> {
    let mut image = vec![0; 0x1002];
    image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (offset, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 1)] {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(20, 1_u32), (64, 1), (68, 5)] {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (24, 0x20_0000_u64),
        (32, 64),
        (72, 0x1000),
        (80, 0x20_0000),
        (88, 0x20_0000),
        (96, 2),
        (104, 0x1000),
        (112, 0x1000),
    ] {
        image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    image[0x1000..].copy_from_slice(&[0x0f, 0x0b]);
    image
}

/// [`host_resources_test_image`] padded with zeros to
/// [`HOST_RESOURCES_PADDED_IMAGE`] bytes. The padding lies past its only
/// segment, so the image loads exactly as before; only the file, and so every
/// buffer an exec reads or copies it into, grows.
fn host_resources_padded_test_image() -> Vec<u8> {
    let mut image = host_resources_test_image();
    image.resize(HOST_RESOURCES_PADDED_IMAGE, 0);
    image
}

/// The size of [`host_resources_padded_test_image`]: 64 MiB.
const HOST_RESOURCES_PADDED_IMAGE: usize = 64 * 1024 * 1024;

/// The guest memory the exec tests run in, so each exec's validation memory:
/// 32 MiB.
const HOST_RESOURCES_MEMORY: usize = 32 * 1024 * 1024;

/// The environment variable that names the test an isolated child runs.
const HOST_RESOURCES_CHILD_ENV: &str = "REVERIE_KVM_EXEC_HOST_RESOURCES_CHILD";

/// This process's address-space size (`VmSize`), in bytes.
fn host_resources_address_space_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmSize:"))
        .and_then(|value| value.trim().strip_suffix("kB"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .expect("/proc/self/status names VmSize in kB");
    kib * 1024
}

/// Whether this process is the isolated child that runs `test`
/// ([`host_resources_run_isolated`]).
fn host_resources_is_child(test: &str) -> bool {
    std::env::var(HOST_RESOURCES_CHILD_ENV).as_deref() == Ok(test)
}

/// Runs `executor::tests::<test>` in a child process of this test binary and
/// asserts that it passed. A child, because the test lowers a limit of its
/// own process, which must bind no other test.
fn host_resources_run_isolated(test: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg(format!("executor::tests::{test}"))
        .arg("--exact")
        .env(HOST_RESOURCES_CHILD_ENV, test)
        .output()
        .expect("failed to run the isolated host-resources check");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "isolated host-resources check {test} failed with {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Runs `f` with this process's soft `RLIMIT_AS` lowered to `headroom` bytes
/// above its address space now, as a supervisor whose limit was lowered while
/// it ran would be, then restores the original limits. Returns `f`'s result
/// and the lowered limit.
fn host_resources_with_address_space_headroom<T>(headroom: u64, f: impl FnOnce() -> T) -> (T, u64) {
    let mut original = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes only `original`.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) },
        0
    );
    let limit = (host_resources_address_space_bytes() + headroom).min(original.rlim_max);
    let lowered = libc::rlimit {
        rlim_cur: limit,
        rlim_max: original.rlim_max,
    };
    // SAFETY: setrlimit reads only `lowered`; only the soft limit drops, so
    // the original can be restored without privilege.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &lowered) }, 0);
    let result = f();
    // SAFETY: as above, with the original limits.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) }, 0);
    (result, limit)
}

/// Guest addresses of the exec request's path, argv and envp.
const HOST_RESOURCES_PATH_ADDRESS: u64 = 0x200;
const HOST_RESOURCES_ARGV_ADDRESS: u64 = 0x1200;
const HOST_RESOURCES_ENVP_ADDRESS: u64 = 0x1300;

/// Writes `execve(path, [path], [])` into `memory` and returns the request.
fn host_resources_exec_request(memory: &mut GuestMemory, path: &[u8]) -> SyscallRequest {
    let path = CString::new(path).unwrap();
    memory
        .write(HOST_RESOURCES_PATH_ADDRESS, path.as_bytes_with_nul())
        .unwrap();
    memory
        .write(
            HOST_RESOURCES_ARGV_ADDRESS,
            &HOST_RESOURCES_PATH_ADDRESS.to_le_bytes(),
        )
        .unwrap();
    memory
        .write(HOST_RESOURCES_ARGV_ADDRESS + 8, &0_u64.to_le_bytes())
        .unwrap();
    memory
        .write(HOST_RESOURCES_ENVP_ADDRESS, &0_u64.to_le_bytes())
        .unwrap();
    SyscallRequest::new(
        libc::SYS_execve as u64,
        [
            HOST_RESOURCES_PATH_ADDRESS,
            HOST_RESOURCES_ARGV_ADDRESS,
            HOST_RESOURCES_ENVP_ADDRESS,
            0,
            0,
            0,
        ],
    )
}

/// Writes `image` to `path`, executable by its owner.
fn host_resources_write_executable(path: &std::path::Path, image: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, image).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Execs `request` from `leader` with this process's soft `RLIMIT_AS`
/// lowered to `headroom` above its address space, then checks that the exec
/// was refused, ENOMEM with the typed `HostResources` refusal whose
/// diagnostic holds every one of `named` and names the lowered limit, and
/// that it published no replacement and left the old image's memory and
/// identity untouched. Then, with the limit restored, execs the same request
/// again: it publishes the exec, so the request was valid all along and only
/// the host refused it. Returns the refusal's diagnostic.
fn host_resources_assert_refused_then_admitted(
    leader: &mut ElfExecutor,
    memory: &mut GuestMemory,
    request: &SyscallRequest,
    headroom: u64,
    named: &[String],
) -> &'static str {
    const SENTINEL_ADDRESS: u64 = 0x30_0000;
    const SENTINEL: [u8; 8] = *b"old-live";
    memory.write(SENTINEL_ADDRESS, &SENTINEL).unwrap();
    let identity = (leader.state.pid, leader.state.tid);

    let ((result, refusal, action), limit) =
        host_resources_with_address_space_headroom(headroom, || {
            let result = leader.execute_process_action(request, memory);
            (
                result,
                leader.take_unsupported_refusal(),
                leader.take_process_action(),
            )
        });

    assert_eq!(result, Some(negative_errno(libc::ENOMEM)));
    let refusal = refusal.expect("a refused host resource carries the typed refusal");
    assert_eq!(
        refusal.operation,
        reverie::UnsupportedOperation::HostResources
    );
    assert_eq!(refusal.errno, reverie::Errno::ENOMEM);
    let mut expected = named.to_vec();
    expected.push(format!("RLIMIT_AS (soft {limit} bytes, "));
    for named in expected {
        assert!(
            refusal.diagnostic.contains(&named),
            "{named:?} missing from {:?}",
            refusal.diagnostic
        );
    }
    assert!(action.is_none(), "a refused exec published a replacement");
    let mut observed = [0; SENTINEL.len()];
    memory.read(SENTINEL_ADDRESS, &mut observed).unwrap();
    assert_eq!(observed, SENTINEL);
    assert_eq!((leader.state.pid, leader.state.tid), identity);

    assert_eq!(leader.execute_process_action(request, memory), Some(0));
    assert_eq!(leader.take_unsupported_refusal(), None);
    assert!(matches!(
        leader.take_process_action(),
        Some(ProcessAction::Exec { .. })
    ));
    refusal.diagnostic
}

/// An exec validates its new image in a second guest memory as large as the
/// live one before it replaces the old image. Here an isolated child lowers
/// its own soft `RLIMIT_AS` to leave that reservation half the room it
/// needs, as a supervisor whose guests outgrew its limit would be. The exec
/// is the typed `HostResources` refusal, answered ENOMEM, naming the
/// reservation and the limit; no exec is published and the old image, its
/// memory and its identity are untouched. With the limit raised again, the
/// same request publishes the exec, so the request was valid all along.
#[test]
fn an_exec_whose_validation_memory_the_host_refuses_is_refused_as_host_resources() {
    const TEST: &str =
        "an_exec_whose_validation_memory_the_host_refuses_is_refused_as_host_resources";
    if !host_resources_is_child(TEST) {
        return host_resources_run_isolated(TEST);
    }
    let root = TestDir::new();
    let path = root.0.join("valid");
    host_resources_write_executable(&path, &host_resources_test_image());
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let request = host_resources_exec_request(&mut memory, path.as_os_str().as_bytes());
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    host_resources_assert_refused_then_admitted(
        &mut leader,
        &mut memory,
        &request,
        HOST_RESOURCES_MEMORY as u64 / 2,
        &[
            "host address space ran out".to_owned(),
            format!("reserving {HOST_RESOURCES_MEMORY} bytes of host address space"),
        ],
    );
}

/// The case an adversarial review found aborting the supervisor: an exec of
/// the caller's own `/proc/self/exe`, whose image (a 64 MiB file, padded past
/// its only segment) the exec copies, under a limit lowered after launch to
/// just above what the process uses. Before, the copy's allocation failure
/// aborted the whole process ("memory allocation of N bytes failed"); now the
/// buffer is allocated fallibly and the exec is the typed refusal naming the
/// request, with nothing published, and the same exec succeeds once the limit
/// is raised.
#[test]
fn an_exec_of_proc_self_exe_whose_image_copy_the_host_refuses_is_refused_as_host_resources() {
    const TEST: &str =
        "an_exec_of_proc_self_exe_whose_image_copy_the_host_refuses_is_refused_as_host_resources";
    if !host_resources_is_child(TEST) {
        return host_resources_run_isolated(TEST);
    }
    let root = TestDir::new();
    let path = root.0.join("padded");
    let image = host_resources_padded_test_image();
    host_resources_write_executable(&path, &image);
    let mut state = test_state(&root.0);
    state.executable_file = Some(Arc::new(std::fs::File::open(&path).unwrap()));
    state.executable_image = Arc::new(image);
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let request = host_resources_exec_request(&mut memory, b"/proc/self/exe");
    let mut leader = ElfExecutor::new(state, false);
    host_resources_assert_refused_then_admitted(
        &mut leader,
        &mut memory,
        &request,
        16 * 1024 * 1024,
        &[format!(
            "host memory ran out: allocating {HOST_RESOURCES_PADDED_IMAGE} bytes for a copy of \
             the running program's image (/proc/self/exe) failed"
        )],
    );
}

/// An exec reads its new image into a buffer as large as the file. Under a
/// limit that leaves less room than the file needs, the buffer is refused by
/// name, naming the request, rather than answered with the guest's EIO or
/// aborting the process.
#[test]
fn an_exec_whose_image_the_host_cannot_buffer_is_refused_as_host_resources() {
    const TEST: &str = "an_exec_whose_image_the_host_cannot_buffer_is_refused_as_host_resources";
    if !host_resources_is_child(TEST) {
        return host_resources_run_isolated(TEST);
    }
    let root = TestDir::new();
    let path = root.0.join("padded");
    host_resources_write_executable(&path, &host_resources_padded_test_image());
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let request = host_resources_exec_request(&mut memory, path.as_os_str().as_bytes());
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    host_resources_assert_refused_then_admitted(
        &mut leader,
        &mut memory,
        &request,
        16 * 1024 * 1024,
        &[format!(
            "host memory ran out: allocating {HOST_RESOURCES_PADDED_IMAGE} bytes for the new \
             program's image failed"
        )],
    );
}

/// The loader keeps a copy of every image it loads, the one a later exec of
/// `/proc/self/exe` reads, and loads each image twice for an exec: into the
/// validation memory, then, past the point of no return, into the live
/// memory. Here the limit leaves room for the image's read and the
/// validation memory, but not for the loader's copy: the copy's allocation
/// is fallible, so the validation load reports the host error and the exec
/// is refused by name. The live load allocates the same copy the same way.
#[test]
fn an_exec_whose_image_the_loader_cannot_copy_is_refused_as_host_resources() {
    const TEST: &str = "an_exec_whose_image_the_loader_cannot_copy_is_refused_as_host_resources";
    if !host_resources_is_child(TEST) {
        return host_resources_run_isolated(TEST);
    }
    let root = TestDir::new();
    let path = root.0.join("padded");
    host_resources_write_executable(&path, &host_resources_padded_test_image());
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let request = host_resources_exec_request(&mut memory, path.as_os_str().as_bytes());
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    // The image's read buffer and the validation memory fit, with 16 MiB to
    // spare; the loader's 64 MiB copy does not.
    let headroom = (HOST_RESOURCES_PADDED_IMAGE + HOST_RESOURCES_MEMORY + 16 * 1024 * 1024) as u64;
    host_resources_assert_refused_then_admitted(
        &mut leader,
        &mut memory,
        &request,
        headroom,
        &[
            "host memory ran out: loading the new image into the validation memory failed"
                .to_owned(),
            format!(
                "allocating {HOST_RESOURCES_PADDED_IMAGE} bytes of host memory for a copy of the \
                 new image"
            ),
        ],
    );
}

/// The loader reads an image's ELF header and program headers only, as
/// Linux's ELF loader does, so an image whose section-header table fills its
/// 64 MiB file costs the exec nothing for its metadata. A full parse would
/// allocate the section table (about a million entries) and an index of the
/// string table it names, sized by the file and infallibly, and a host short of
/// memory would abort the process. Here the limit leaves room for the image's
/// read buffer, the validation memory and the loader's copy of the image, 16 MiB
/// to spare, and not for that metadata: the exec is published.
#[test]
fn an_exec_of_an_image_with_vast_section_metadata_reads_only_its_program_headers() {
    const TEST: &str =
        "an_exec_of_an_image_with_vast_section_metadata_reads_only_its_program_headers";
    if !host_resources_is_child(TEST) {
        return host_resources_run_isolated(TEST);
    }
    let root = TestDir::new();
    let path = root.0.join("vast-sections");
    host_resources_write_executable(
        &path,
        &crate::elf::minimal_test_elf_with_vast_metadata(
            &[0x0f, 0x0b],
            HOST_RESOURCES_PADDED_IMAGE,
        ),
    );
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let request = host_resources_exec_request(&mut memory, path.as_os_str().as_bytes());
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    let headroom =
        (2 * HOST_RESOURCES_PADDED_IMAGE + HOST_RESOURCES_MEMORY + 16 * 1024 * 1024) as u64;
    let ((result, refusal, action), _) =
        host_resources_with_address_space_headroom(headroom, || {
            let result = leader.execute_process_action(&request, &memory);
            (
                result,
                leader.take_unsupported_refusal(),
                leader.take_process_action(),
            )
        });
    assert_eq!(result, Some(0), "refusal: {refusal:?}");
    assert_eq!(refusal, None);
    assert!(matches!(action, Some(ProcessAction::Exec { .. })));
}

/// A PT_INTERP larger than Linux reads (`PATH_MAX`) is refused with Linux's
/// ENOEXEC before the loader copies the path it holds. Here one fills the
/// image's 64 MiB file: natively the exec is ENOEXEC, and here too, under a
/// limit that leaves room for the image's read buffer and the validation
/// memory, 16 MiB to spare, and not for a copy of that path. A loader that
/// copied the path first would abort the process.
#[test]
fn an_exec_whose_pt_interp_linux_refuses_is_enoexec_before_its_path_is_copied() {
    const TEST: &str = "an_exec_whose_pt_interp_linux_refuses_is_enoexec_before_its_path_is_copied";
    if !host_resources_is_child(TEST) {
        return host_resources_run_isolated(TEST);
    }
    let root = TestDir::new();
    let path = root.0.join("vast-interpreter");
    let mut interpreter = vec![b'a'; HOST_RESOURCES_PADDED_IMAGE - 0x2000];
    interpreter[0] = b'/';
    *interpreter.last_mut().unwrap() = 0;
    host_resources_write_executable(
        &path,
        &crate::elf::minimal_test_elf_with_interpreter(&[0x0f, 0x0b], &interpreter),
    );
    drop(interpreter);
    let native = std::process::Command::new(&path)
        .output()
        .expect_err("Linux refuses the exec");
    assert_eq!(native.raw_os_error(), Some(libc::ENOEXEC), "{native}");
    let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
    let request = host_resources_exec_request(&mut memory, path.as_os_str().as_bytes());
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    let headroom = (HOST_RESOURCES_PADDED_IMAGE + HOST_RESOURCES_MEMORY + 16 * 1024 * 1024) as u64;
    let ((result, refusal, action), _) =
        host_resources_with_address_space_headroom(headroom, || {
            let result = leader.execute_process_action(&request, &memory);
            (
                result,
                leader.take_unsupported_refusal(),
                leader.take_process_action(),
            )
        });
    assert_eq!(
        result,
        Some(negative_errno(libc::ENOEXEC)),
        "refusal: {refusal:?}"
    );
    assert_eq!(refusal, None);
    assert!(action.is_none());
}

/// An interpreter with more than a page of program headers runs. Linux has
/// read tables of up to 64 KiB (1170 entries) since 6.17, which dropped the
/// one-page bound (kernel commit 8030790477e8), and this loader follows it.
/// A program whose interpreter has 74, or 1170, program headers runs natively
/// (the interpreter exits 0) and its exec is published here.
#[test]
fn an_exec_whose_interpreter_has_more_than_a_page_of_program_headers_runs() {
    // mov eax, 60 (exit); xor edi, edi; syscall
    const EXIT_ZERO: [u8; 9] = [0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];
    for headers in [74_u16, 1170] {
        let root = TestDir::new();
        let interpreter = root.0.join("interpreter");
        host_resources_write_executable(
            &interpreter,
            &crate::elf::minimal_test_interpreter(&EXIT_ZERO, headers),
        );
        let mut interpreter_path = interpreter.as_os_str().as_bytes().to_vec();
        interpreter_path.push(0);
        let program = root.0.join("program");
        host_resources_write_executable(
            &program,
            &crate::elf::minimal_test_elf_with_interpreter(&[0x0f, 0x0b], &interpreter_path),
        );
        let native = std::process::Command::new(&program).status().unwrap();
        assert_eq!(
            native.code(),
            Some(0),
            "{headers} headers natively: {native:?}"
        );
        let mut memory = GuestMemory::new(0, HOST_RESOURCES_MEMORY).unwrap();
        let request = host_resources_exec_request(&mut memory, program.as_os_str().as_bytes());
        let mut leader = ElfExecutor::new(test_state(&root.0), false);
        let result = leader.execute_process_action(&request, &memory);
        let refusal = leader.take_unsupported_refusal();
        assert_eq!(result, Some(0), "{headers} headers: {refusal:?}");
        assert_eq!(refusal, None);
        assert!(matches!(
            leader.take_process_action(),
            Some(ProcessAction::Exec { .. })
        ));
    }
}

/// The refusal of a validation memory names the host's error and what ran
/// out, with the limit it ran out under: address space and `RLIMIT_AS` for
/// ENOMEM or an allocation's OutOfMemory, descriptors and `RLIMIT_NOFILE`
/// for EMFILE (the memfd behind the memory needs one).
#[test]
fn a_refused_validation_memory_names_the_request_the_error_and_the_limit() {
    let out_of_memory = exec_validation_memory_refusal(
        4096,
        &crate::Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::ENOMEM)),
    );
    let allocation = exec_validation_memory_refusal(
        4096,
        &crate::Error::MemoryMapping(std::io::Error::from(std::io::ErrorKind::OutOfMemory)),
    );
    let descriptors = exec_validation_memory_refusal(
        8192,
        &crate::Error::HostIo(std::io::Error::from_raw_os_error(libc::EMFILE)),
    );
    for refusal in [out_of_memory, allocation, descriptors] {
        assert_eq!(
            refusal.operation,
            reverie::UnsupportedOperation::HostResources
        );
        assert_eq!(refusal.errno, reverie::Errno::ENOMEM);
    }
    for refusal in [out_of_memory, allocation] {
        assert!(
            refusal
                .diagnostic
                .contains("host address space ran out: reserving 4096 bytes"),
            "{}",
            refusal.diagnostic
        );
        assert!(
            refusal
                .diagnostic
                .contains("under this process's RLIMIT_AS (soft "),
            "{}",
            refusal.diagnostic
        );
    }
    assert!(
        out_of_memory
            .diagnostic
            .contains(&std::io::Error::from_raw_os_error(libc::ENOMEM).to_string())
    );
    assert!(
        descriptors
            .diagnostic
            .contains("host file descriptors ran out: reserving 8192 bytes"),
        "{}",
        descriptors.diagnostic
    );
    assert!(
        descriptors
            .diagnostic
            .contains("under this process's RLIMIT_NOFILE (soft "),
        "{}",
        descriptors.diagnostic
    );
    assert!(
        descriptors
            .diagnostic
            .contains(&std::io::Error::from_raw_os_error(libc::EMFILE).to_string())
    );
}

/// A host call an exec makes (opening the image, reading it) that fails for
/// want of a host resource of this process's own is refused by name: ENOMEM,
/// and a refusal naming the resource, the step, the error and the limit.
/// Every other failure is the guest's errno, unchanged, with no refusal.
#[test]
fn an_exec_step_refuses_only_the_host_resources_it_ran_out_of() {
    for (errno, named) in [
        (
            libc::EMFILE,
            "host file descriptors ran out: opening the new program failed",
        ),
        (
            libc::ENFILE,
            "the host's file table ran out: opening the new program failed",
        ),
        (
            libc::ENOMEM,
            "host memory ran out: opening the new program failed",
        ),
    ] {
        let mut refusal = None;
        assert_eq!(
            exec_step_errno(
                negative_errno(errno),
                "opening the new program",
                &mut refusal
            ),
            negative_errno(libc::ENOMEM)
        );
        let refusal = refusal.expect("a host resource that ran out is refused");
        assert_eq!(
            refusal.operation,
            reverie::UnsupportedOperation::HostResources
        );
        assert!(
            refusal
                .diagnostic
                .starts_with(&format!("KVM exec: {named}")),
            "{}",
            refusal.diagnostic
        );
    }
    for errno in [
        libc::ENOENT,
        libc::EACCES,
        libc::ELOOP,
        libc::ENOTDIR,
        libc::ENAMETOOLONG,
        libc::EIO,
    ] {
        let mut refusal = None;
        assert_eq!(
            exec_step_errno(
                negative_errno(errno),
                "opening the new program",
                &mut refusal
            ),
            negative_errno(errno)
        );
        assert_eq!(refusal, None, "{errno}");
        assert_eq!(
            exec_step_io_error(
                std::io::Error::from_raw_os_error(errno),
                "reading the new program's image",
                &mut refusal
            ),
            negative_errno(errno)
        );
        assert_eq!(refusal, None, "{errno}");
    }
    let mut refusal = None;
    assert_eq!(
        exec_step_io_error(
            std::io::Error::from(std::io::ErrorKind::OutOfMemory),
            "reading the new program's image",
            &mut refusal
        ),
        negative_errno(libc::ENOMEM)
    );
    assert!(refusal.is_some_and(|refusal| {
        refusal
            .diagnostic
            .contains("host memory ran out: reading the new program's image failed")
    }),);
}

/// Every ENOMEM an exec preparation returns is the host's, and carries the
/// refusal; no other result does, ENOSYS included (a nonleader exec's own
/// refusal, decided after this one).
#[test]
fn only_an_exec_preparation_enomem_is_a_host_resources_refusal() {
    let refusal = exec_host_memory_refusal(negative_errno(libc::ENOMEM))
        .expect("an exec preparation ENOMEM is the host's");
    assert_eq!(
        refusal.operation,
        reverie::UnsupportedOperation::HostResources
    );
    assert_eq!(refusal.errno, reverie::Errno::ENOMEM);
    assert!(refusal.diagnostic.starts_with(HOST_RESOURCES_REFUSAL));
    assert!(
        refusal
            .diagnostic
            .contains("under this process's RLIMIT_AS (soft ")
    );
    for result in [
        0,
        negative_errno(libc::EFAULT),
        negative_errno(libc::ENOENT),
        negative_errno(libc::EACCES),
        negative_errno(libc::ENOEXEC),
        negative_errno(libc::E2BIG),
        negative_errno(libc::EBUSY),
        negative_errno(libc::ENOTSUP),
        negative_errno(libc::ENOSYS),
        negative_errno(libc::EIO),
    ] {
        assert_eq!(exec_host_memory_refusal(result), None, "{result}");
    }
}

/// A loader failure is this backend's only when a host resource of this
/// process's own ran out (memory, a descriptor, the host's file table); a
/// malformed image, one too large for the guest memory (the out-of-bounds
/// address its segments reach) or any other host error stays the guest's
/// ENOEXEC.
#[test]
fn loader_host_resource_errors_are_told_apart_from_image_errors() {
    for error in [
        crate::Error::HostIo(std::io::Error::from_raw_os_error(libc::ENOMEM)),
        crate::Error::HostIo(std::io::Error::from(std::io::ErrorKind::OutOfMemory)),
        crate::Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::ENOMEM)),
        crate::Error::HostIo(std::io::Error::from_raw_os_error(libc::EMFILE)),
        crate::Error::HostIo(std::io::Error::from_raw_os_error(libc::ENFILE)),
        crate::Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::EMFILE)),
    ] {
        assert!(error.host_resource_exhaustion().is_some(), "{error}");
    }
    for error in [
        crate::Error::HostIo(std::io::Error::from_raw_os_error(libc::EACCES)),
        crate::Error::HostIo(std::io::Error::from_raw_os_error(libc::ENOENT)),
        crate::Error::UnsupportedElf("not an ELF image".to_owned()),
        crate::Error::LongModeMemoryTooSmall,
        crate::Error::InvalidGuestAddress {
            address: 0x1_0000_0000,
            length: 0x1000,
            guest_base: 0,
            guest_end: HOST_RESOURCES_MEMORY as u64,
        },
    ] {
        assert!(error.host_resource_exhaustion().is_none(), "{error}");
    }
}

/// Each distinct diagnostic is kept once and found again; past the bound a
/// new one falls back to the fixed diagnostic, and a kept one is still found.
#[test]
fn host_resources_diagnostics_are_kept_once_each_up_to_the_bound() {
    let mut kept = Vec::new();
    let first = keep_host_resources_diagnostic(&mut kept, "first".to_owned());
    assert!(std::ptr::eq(
        first,
        keep_host_resources_diagnostic(&mut kept, "first".to_owned())
    ));
    assert_eq!(kept.len(), 1);
    for index in 1..MAX_HOST_RESOURCES_DIAGNOSTICS {
        keep_host_resources_diagnostic(&mut kept, format!("text {index}"));
    }
    assert_eq!(kept.len(), MAX_HOST_RESOURCES_DIAGNOSTICS);
    assert_eq!(
        keep_host_resources_diagnostic(&mut kept, "past the bound".to_owned()),
        HOST_RESOURCES_REFUSAL
    );
    assert_eq!(kept.len(), MAX_HOST_RESOURCES_DIAGNOSTICS);
    assert!(std::ptr::eq(
        first,
        keep_host_resources_diagnostic(&mut kept, "first".to_owned())
    ));
}
