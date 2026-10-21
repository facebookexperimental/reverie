use super::*;

fn run_exhaustion(test: &str, vector: bool, with_tool: bool) {
    Kvm::new().unwrap_or_else(|error| panic!("{test} requires usable /dev/kvm: {error}"));
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "random-device-stream",
        include_str!("../fixtures/random_device_stream.c"),
    );
    let mode = if vector { "vector" } else { "scalar" };
    let expected = format!("{mode} total=69632\n").into_bytes();
    let native = std::process::Command::new(&executable)
        .arg(mode)
        .output()
        .unwrap();
    assert!(native.status.success(), "native: {native:?}");
    assert_eq!(native.stdout, expected);
    assert!(native.stderr.is_empty(), "native: {native:?}");
    eprintln!("native {mode}: 69632 bytes, exit 0");
    for repetition in 0..2 {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap(), mode],
                &[],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if with_tool {
            let (log, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            let name = if vector { "readv" } else { "read" };
            let calls = log.syscalls().iter().filter(|call| *call == name).count();
            assert!(calls >= 17, "random reads must reach the Tool: {calls}");
            eprintln!("Tool {name} callbacks={calls}");
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        eprintln!(
            "KVM {mode} tool={with_tool} repetition={repetition}: code={code} stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(code, 0);
        assert_eq!(stdout, expected);
        assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    }
}

#[test]
fn random_device_scalar_stream_direct() {
    run_exhaustion("random_device_scalar_stream_direct", false, false);
}

#[test]
fn random_device_scalar_stream_tool() {
    run_exhaustion("random_device_scalar_stream_tool", false, true);
}

#[test]
fn random_device_vector_stream_direct() {
    run_exhaustion("random_device_vector_stream_direct", true, false);
}

#[test]
fn random_device_vector_stream_tool() {
    run_exhaustion("random_device_vector_stream_tool", true, true);
}

fn run_partitioned_contract(with_tool: bool) {
    Kvm::new().expect("random stream byte contract requires usable /dev/kvm");
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "random-device-partitions",
        include_str!("../fixtures/random_device_stream.c"),
    );
    let native = std::process::Command::new(&executable)
        .arg("partitioned")
        .output()
        .unwrap();
    assert!(native.status.success(), "native: {native:?}");
    assert!(native.stderr.is_empty());
    assert_eq!(native.stdout.len(), 70001);
    // Independent oracle for the pre-existing seed-zero byte contract. Never
    // obtain expected bytes from the implementation's carrier or generator.
    let expected: Vec<u8> = (0..70001u64)
        .map(|index| ((index * 73 + 41) & 255) as u8)
        .collect();
    for _ in 0..2 {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap(), "partitioned"],
                &[],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if with_tool {
            let (log, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            assert!(log.syscalls().iter().any(|call| call == "readv"));
            assert!(log.syscalls().iter().any(|call| call == "dup"));
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert_eq!(
            stdout, expected,
            "each byte must follow the original stream across syscall and alias boundaries"
        );
    }
}

#[test]
fn random_device_partitioned_byte_contract_direct() {
    run_partitioned_contract(false);
}

#[test]
fn random_device_partitioned_byte_contract_tool() {
    run_partitioned_contract(true);
}
