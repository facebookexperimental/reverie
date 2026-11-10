// Included inside vm::tests: an exec that the host cannot finish past its
// point of no return ends in the named refusal `Error::HostResources`, never
// in an abort of the process or a backend fault.

/// The guest memory these tests run in: 16 MiB.
const EXEC_HOST_RESOURCES_MEMORY: usize = 16 * 1024 * 1024;

/// The size of [`exec_host_resources_padded_image`]: 64 MiB.
const EXEC_HOST_RESOURCES_IMAGE: usize = 64 * 1024 * 1024;

/// The environment variable that marks the isolated child.
const EXEC_HOST_RESOURCES_CHILD_ENV: &str = "REVERIE_KVM_EXEC_PAST_POINT_OF_NO_RETURN_CHILD";

/// A backend with a minimal static ELF installed, and that image's executor;
/// `None` where KVM is unavailable and not required.
fn exec_host_resources_backend() -> Option<(KvmBackend, ElfExecutor)> {
    let mut backend = match KvmBackend::new(EXEC_HOST_RESOURCES_MEMORY) {
        Ok(backend) => backend,
        Err(error) => {
            if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() {
                panic!("KVM is required: {error}");
            }
            eprintln!("skipping exec host-resources KVM test: {error}");
            return None;
        }
    };
    backend
        .install_static_elf(&minimal_test_elf(&[HLT]), "/bin/exec-host-resources")
        .unwrap();
    let executor = ElfExecutor::new(backend.static_elf.take().unwrap(), false);
    Some((backend, executor))
}

/// [`minimal_test_elf`] padded with zeros past its only segment to 64 MiB:
/// it loads as before, but the copy of it the loader keeps is 64 MiB.
fn exec_host_resources_padded_image() -> Vec<u8> {
    let mut image = minimal_test_elf(&[HLT]);
    image.resize(EXEC_HOST_RESOURCES_IMAGE, 0);
    image
}

/// This process's address-space size (`VmSize`), in bytes.
fn exec_host_resources_address_space_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmSize:"))
        .and_then(|value| value.trim().strip_suffix("kB"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .expect("/proc/self/status names VmSize in kB");
    kib * 1024
}

/// An exec whose image passed its preflight replaces the old image from its
/// point of no return on (`KvmBackend::exec_process`), loading the image a
/// second time, into the live memory. Here the host refuses that load: an
/// isolated child lowers its own soft `RLIMIT_AS` once the backend exists,
/// to 16 MiB above what it uses, so the 64 MiB copy of the image the loader
/// keeps cannot be allocated, as it could not be for a supervisor whose limit
/// was lowered between an exec's preflight and its commit. The copy is
/// allocated fallibly, and the exec ends with the named refusal
/// `Error::HostResources`, naming the step, the request and the limit: not an
/// abort of the process ("memory allocation of N bytes failed"), and not a
/// backend fault. A fresh backend execs the same image once the limit is
/// restored, so only the host refused it.
#[test]
fn an_exec_the_host_cannot_finish_past_its_point_of_no_return_is_the_host_resources_refusal() {
    const TEST: &str = "vm::tests::an_exec_the_host_cannot_finish_past_its_point_of_no_return_is_the_host_resources_refusal";
    if std::env::var_os(EXEC_HOST_RESOURCES_CHILD_ENV).is_none() {
        if exec_host_resources_backend().is_none() {
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(TEST)
            .arg("--exact")
            .env(EXEC_HOST_RESOURCES_CHILD_ENV, "1")
            .output()
            .expect("failed to run the isolated exec host-resources check");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "isolated exec host-resources check failed with {}\nstdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let (mut backend, mut executor) =
        exec_host_resources_backend().expect("the parent found KVM available");
    let image = exec_host_resources_padded_image();
    let argv = ["/bin/exec-host-resources-padded".to_owned()];
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
        (exec_host_resources_address_space_bytes() + 16 * 1024 * 1024).min(original.rlim_max);
    let lowered = libc::rlimit {
        rlim_cur: limit,
        rlim_max: original.rlim_max,
    };
    // SAFETY: setrlimit reads only `lowered`; only the soft limit drops, so
    // the original can be restored without privilege.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &lowered) }, 0);
    let result = backend.exec_process(
        &mut executor,
        (Path::new(&argv[0]), None),
        None,
        &image,
        &argv,
        &[],
    );
    // SAFETY: as above, with the original limits.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) }, 0);

    let error = result.expect_err("the host refused the new image's copy");
    assert!(error.is_host_resources_refusal(), "{error}");
    let Error::HostResources {
        resource,
        diagnostic,
    } = &error
    else {
        panic!("not the named refusal: {error}");
    };
    assert_eq!(*resource, crate::HostResource::Memory);
    for named in [
        "KVM exec: host memory ran out after the old image was discarded: replacing the image \
         failed"
            .to_owned(),
        format!(
            "allocating {EXEC_HOST_RESOURCES_IMAGE} bytes of host memory for a copy of the new \
             image"
        ),
        format!("under this process's RLIMIT_AS (soft {limit} bytes, "),
        "the old image cannot be restored, so the run ends here".to_owned(),
    ] {
        assert!(
            diagnostic.contains(&named),
            "{named:?} missing from {diagnostic:?}"
        );
    }
    drop(executor);
    drop(backend);

    let (mut backend, mut executor) =
        exec_host_resources_backend().expect("the parent found KVM available");
    backend
        .exec_process(
            &mut executor,
            (Path::new(&argv[0]), None),
            None,
            &image,
            &argv,
            &[],
        )
        .expect("the same exec succeeds under the original limit");
}

/// The reload past an exec's point of no return reads the new image's ELF
/// header and program headers only, as Linux's ELF loader does. An image
/// whose section-header table fills its 64 MiB file costs the reload nothing
/// for that metadata, where a full parse would allocate the section table and
/// a string-table index, sized by the file and infallibly, before the loader's
/// copy of the image. Here an isolated child lowers its limit to leave room
/// for that copy, with 16 MiB to spare, and not for the metadata: the reload
/// succeeds.
#[test]
fn an_exec_reload_of_an_image_with_vast_section_metadata_reads_only_its_program_headers() {
    const TEST: &str = "vm::tests::an_exec_reload_of_an_image_with_vast_section_metadata_reads_only_its_program_headers";
    if std::env::var_os(EXEC_HOST_RESOURCES_CHILD_ENV).is_none() {
        if exec_host_resources_backend().is_none() {
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(TEST)
            .arg("--exact")
            .env(EXEC_HOST_RESOURCES_CHILD_ENV, "1")
            .output()
            .expect("failed to run the isolated exec reload check");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "isolated exec reload check failed with {}\nstdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let (mut backend, mut executor) =
        exec_host_resources_backend().expect("the parent found KVM available");
    let image = crate::elf::minimal_test_elf_with_vast_metadata(&[HLT], EXEC_HOST_RESOURCES_IMAGE);
    let argv = ["/bin/exec-vast-section-metadata".to_owned()];
    let mut original = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes only `original`.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) },
        0
    );
    let limit = (exec_host_resources_address_space_bytes()
        + EXEC_HOST_RESOURCES_IMAGE as u64
        + 16 * 1024 * 1024)
        .min(original.rlim_max);
    let lowered = libc::rlimit {
        rlim_cur: limit,
        rlim_max: original.rlim_max,
    };
    // SAFETY: setrlimit reads only `lowered`; only the soft limit drops, so
    // the original can be restored without privilege.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &lowered) }, 0);
    let result = backend.exec_process(
        &mut executor,
        (Path::new(&argv[0]), None),
        None,
        &image,
        &argv,
        &[],
    );
    // SAFETY: as above, with the original limits.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) }, 0);
    result.expect("the reload needs no memory for section metadata");
}

/// Only a host resource of this process's own that ran out becomes the named
/// refusal past an exec's point of no return, whether a host call, a fallible
/// allocation or a KVM ioctl reported it, and the refusal carries the
/// resource. Any other error, an ordinary ioctl fault included, is returned as
/// it is. The refusal is found beneath the wrappers a run's failure is
/// aggregated in.
#[test]
fn only_a_host_resource_that_ran_out_past_the_point_of_no_return_is_the_named_refusal() {
    use crate::HostResource;
    for (error, expected) in [
        (
            Error::HostIo(std::io::Error::from_raw_os_error(libc::ENOMEM)),
            HostResource::Memory,
        ),
        (
            Error::HostIo(std::io::Error::from(std::io::ErrorKind::OutOfMemory)),
            HostResource::Memory,
        ),
        (
            Error::MemoryMapping(std::io::Error::from_raw_os_error(libc::ENOMEM)),
            HostResource::Memory,
        ),
        (
            Error::HostAllocation {
                what: "a copy of the new image",
                bytes: 4096,
            },
            HostResource::Memory,
        ),
        (
            Error::Kvm(kvm_ioctls::Error::new(libc::ENOMEM)),
            HostResource::Memory,
        ),
        (
            Error::HostIo(std::io::Error::from_raw_os_error(libc::EMFILE)),
            HostResource::Descriptors,
        ),
        (
            Error::Kvm(kvm_ioctls::Error::new(libc::EMFILE)),
            HostResource::Descriptors,
        ),
        (
            Error::HostIo(std::io::Error::from_raw_os_error(libc::ENFILE)),
            HostResource::FileTable,
        ),
        (
            Error::Kvm(kvm_ioctls::Error::new(libc::ENFILE)),
            HostResource::FileTable,
        ),
    ] {
        let refusal = exec_after_point_of_no_return_error(error);
        assert!(refusal.is_host_resources_refusal(), "{refusal}");
        assert!(
            matches!(&refusal, Error::HostResources { resource, .. } if *resource == expected),
            "{refusal}"
        );
        let shared = Arc::new(refusal);
        assert!(Error::SharedFailure(shared.clone()).is_host_resources_refusal());
        assert!(
            Error::WithCleanup {
                primary: shared,
                cleanup: vec![Arc::new(Error::RunAborted)],
            }
            .is_host_resources_refusal()
        );
    }
    for error in [
        Error::HostIo(std::io::Error::from_raw_os_error(libc::EIO)),
        Error::Kvm(kvm_ioctls::Error::new(libc::EINVAL)),
        Error::Kvm(kvm_ioctls::Error::new(libc::EFAULT)),
        Error::UnsupportedElf("not an ELF image".to_owned()),
        Error::LongModeMemoryTooSmall,
        Error::RunAborted,
    ] {
        let text = error.to_string();
        let returned = exec_after_point_of_no_return_error(error);
        assert!(!returned.is_host_resources_refusal(), "{returned}");
        assert_eq!(returned.to_string(), text);
    }
}
