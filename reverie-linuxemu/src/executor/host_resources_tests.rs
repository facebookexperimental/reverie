// Tests of this backend's typed refusal of host resources (refusal.rs): an
// exec the host cannot give the memory it needs is refused by name, never
// answered with an errno the guest would take for one of its own.

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
    const CHILD_ENV: &str = "REVERIE_KVM_EXEC_HOST_ADDRESS_SPACE_CHILD";
    const MEMORY: usize = 32 * 1024 * 1024;
    const SENTINEL_ADDRESS: u64 = 0x30_0000;
    const SENTINEL: [u8; 8] = *b"old-live";
    const PATH_ADDRESS: u64 = 0x200;
    const ARGV_ADDRESS: u64 = 0x400;
    const ENVP_ADDRESS: u64 = 0x500;

    if std::env::var_os(CHILD_ENV).is_some() {
        let root = TestDir::new();
        let path = root.0.join("valid");
        std::fs::write(&path, host_resources_test_image()).unwrap();
        let mut memory = GuestMemory::new(0, MEMORY).unwrap();
        memory.write(SENTINEL_ADDRESS, &SENTINEL).unwrap();
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        memory
            .write(PATH_ADDRESS, path.as_bytes_with_nul())
            .unwrap();
        memory
            .write(ARGV_ADDRESS, &PATH_ADDRESS.to_le_bytes())
            .unwrap();
        memory
            .write(ARGV_ADDRESS + 8, &0_u64.to_le_bytes())
            .unwrap();
        memory.write(ENVP_ADDRESS, &0_u64.to_le_bytes()).unwrap();
        let request = SyscallRequest::new(
            libc::SYS_execve as u64,
            [PATH_ADDRESS, ARGV_ADDRESS, ENVP_ADDRESS, 0, 0, 0],
        );
        let mut leader = ElfExecutor::new(test_state(&root.0), false);
        let identity = (leader.state.pid, leader.state.tid);

        let mut original = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes only `original`.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) },
            0
        );
        let limit =
            (host_resources_address_space_bytes() + MEMORY as u64 / 2).min(original.rlim_max);
        let lowered = libc::rlimit {
            rlim_cur: limit,
            rlim_max: original.rlim_max,
        };
        // SAFETY: setrlimit reads only `lowered`; only the soft limit drops,
        // so the original can be restored without privilege.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &lowered) }, 0);
        let result = leader.execute_process_action(&request, &memory);
        let refusal = leader.take_unsupported_refusal();
        let action = leader.take_process_action();
        // SAFETY: as above, with the original limits.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) }, 0);

        assert_eq!(result, Some(negative_errno(libc::ENOMEM)));
        let refusal = refusal.expect("a refused validation memory carries the typed refusal");
        assert_eq!(
            refusal.operation,
            reverie::UnsupportedOperation::HostResources
        );
        assert_eq!(refusal.errno, reverie::Errno::ENOMEM);
        for named in [
            "host address space ran out".to_owned(),
            format!("reserving {MEMORY} bytes of host address space"),
            format!("RLIMIT_AS (soft {limit} bytes, "),
        ] {
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

        assert_eq!(leader.execute_process_action(&request, &memory), Some(0));
        assert_eq!(leader.take_unsupported_refusal(), None);
        assert!(matches!(
            leader.take_process_action(),
            Some(ProcessAction::Exec { .. })
        ));
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("executor::tests::an_exec_whose_validation_memory_the_host_refuses_is_refused_as_host_resources")
        .arg("--exact")
        .env(CHILD_ENV, "1")
        .output()
        .expect("failed to run the isolated address-space exec check");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "isolated address-space exec check failed with {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The refusal of a validation memory names the host's error and whether it
/// was address space that ran out (ENOMEM, or an allocation's OutOfMemory)
/// or another host resource.
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
        assert!(refusal.diagnostic.contains("RLIMIT_AS (soft "));
    }
    assert!(
        out_of_memory
            .diagnostic
            .contains("host address space ran out: reserving 4096 bytes")
    );
    assert!(
        out_of_memory
            .diagnostic
            .contains(&std::io::Error::from_raw_os_error(libc::ENOMEM).to_string())
    );
    assert!(
        allocation
            .diagnostic
            .contains("host address space ran out: reserving 4096 bytes")
    );
    assert!(
        descriptors
            .diagnostic
            .contains("a host resource ran out: reserving 8192 bytes")
    );
    assert!(
        descriptors
            .diagnostic
            .contains(&std::io::Error::from_raw_os_error(libc::EMFILE).to_string())
    );
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

/// A loader failure is this backend's only when the host ran out of memory;
/// a malformed or oversized image stays the guest's ENOEXEC.
#[test]
fn loader_host_memory_errors_are_told_apart_from_image_errors() {
    for error in [
        crate::Error::HostIo(std::io::Error::from_raw_os_error(libc::ENOMEM)),
        crate::Error::HostIo(std::io::Error::from(std::io::ErrorKind::OutOfMemory)),
        crate::Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::ENOMEM)),
    ] {
        assert!(is_host_memory_error(&error), "{error}");
    }
    for error in [
        crate::Error::HostIo(std::io::Error::from_raw_os_error(libc::EACCES)),
        crate::Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::EMFILE)),
        crate::Error::UnsupportedElf("not an ELF image".to_owned()),
        crate::Error::LongModeMemoryTooSmall,
    ] {
        assert!(!is_host_memory_error(&error), "{error}");
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
