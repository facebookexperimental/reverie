/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(target_arch = "x86_64")]

use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use kvm_ioctls::Kvm;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;
use reverie_kvm::Error;
use reverie_kvm::KvmBackend;
use reverie_kvm::StraceTool;

const MEMORY_SIZE: usize = 16 * 1024 * 1024;
const LOAD_ADDRESS: u64 = 0x20_0000;
const CODE_OFFSET: usize = 0x1000;
const POST_EXEC_RANDOM: [u8; 16] = *b"kvm-post-exec-ok";
static POST_EXEC_FAILURE_EXITED: AtomicBool = AtomicBool::new(false);

static NEXT_TEST_EXECUTABLE: AtomicU64 = AtomicU64::new(0);

struct TestExecutable(PathBuf);

impl TestExecutable {
    fn new(image: &[u8]) -> Self {
        let id = NEXT_TEST_EXECUTABLE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("reverie-kvm-exec-{}-{id}", std::process::id()));
        std::fs::write(&path, image).unwrap();
        Self(path)
    }
}

impl Drop for TestExecutable {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let id = NEXT_TEST_EXECUTABLE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("reverie-kvm-coreutils-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn run_host_program_captured(
    program: &str,
    argv: &[&str],
    cwd: &std::path::Path,
) -> (Vec<u8>, Vec<u8>) {
    const REAL_PROGRAM_MEMORY_SIZE: usize = 256 * 1024 * 1024;

    let image = std::fs::read(program).unwrap();
    let mut backend = KvmBackend::new(REAL_PROGRAM_MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_context(&image, argv, &[], cwd)
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(
        code,
        0,
        "{program} {argv:?} exited {code}; stdout={}; stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
    (stdout, stderr)
}

fn run_host_program(program: &str, argv: &[&str], cwd: &std::path::Path) {
    let _ = run_host_program_captured(program, argv, cwd);
}

#[derive(Default)]
struct PostExecLog {
    at_random: Mutex<Option<usize>>,
}

impl PostExecLog {
    fn at_random(&self) -> Option<usize> {
        *self.at_random.lock().expect("post-exec log lock poisoned")
    }
}

#[reverie::global_tool]
impl GlobalTool for PostExecLog {
    type Request = usize;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, at_random: usize) {
        *self.at_random.lock().expect("post-exec log lock poisoned") = Some(at_random);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PostExecTool;

#[reverie::tool]
impl Tool for PostExecTool {
    type GlobalState = PostExecLog;
    type ThreadState = ();

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        let auxv = guest.auxv();
        let address = auxv.at_random().ok_or(Errno::EINVAL)?;
        guest.send_rpc(address.as_raw()).await;
        // This lifecycle hook runs before the ELF entry point, matching execve.
        let address = unsafe { address.into_mut() };
        guest.memory().write_value(address, &POST_EXEC_RANDOM)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FailingPostExecTool;

#[reverie::tool]
impl Tool for FailingPostExecTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_post_exec<G: Guest<Self>>(&self, _guest: &mut G) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        _global: &G,
        _thread_state: Self::ThreadState,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        POST_EXEC_FAILURE_EXITED.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn kvm_is_unavailable(error: &kvm_ioctls::Error) -> bool {
    matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM)
}

fn assert_invalid_opcode(error: Error) {
    match error {
        Error::GuestException {
            vector,
            instruction_pointer,
            ..
        } => {
            assert_eq!(vector, 6);
            assert_eq!(instruction_pointer, LOAD_ADDRESS);
        }
        error => panic!("expected invalid-opcode exception, got {error}"),
    }
}

fn assert_page_fault(error: Error) {
    match error {
        Error::GuestException {
            vector,
            instruction_pointer,
            fault_address,
        } => {
            assert_eq!(vector, 14);
            assert_eq!(instruction_pointer, LOAD_ADDRESS);
            assert_eq!(fault_address, 0x4000_0000);
        }
        error => panic!("expected page-fault exception, got {error}"),
    }
}

#[test]
fn static_elf_faults_are_reported_by_direct_and_tool_runtimes() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM exception test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let image = static_elf(&[0x0f, 0x0b]);

    let mut direct_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    direct_backend
        .install_static_elf(&image, "/bin/fault")
        .unwrap();
    assert_invalid_opcode(direct_backend.run_static_elf().unwrap_err());

    let mut tool_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    tool_backend
        .install_static_elf(&image, "/bin/fault")
        .unwrap();
    let error = match futures::executor::block_on(
        tool_backend.run_static_elf_with_tool::<StraceTool>((), true),
    ) {
        Ok(_) => panic!("tool runtime reported a guest exception as success"),
        Err(error) => error,
    };
    assert_invalid_opcode(error);

    // movabs rax, qword ptr [0x40000000], an address outside the page tables.
    let page_fault_image =
        static_elf(&[0x48, 0xa1, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00]);
    let mut page_fault_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    page_fault_backend
        .install_static_elf(&page_fault_image, "/bin/fault")
        .unwrap();
    assert_page_fault(page_fault_backend.run_static_elf().unwrap_err());
}

#[test]
fn static_elf_forks_execs_and_waits_for_child() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM multiprocess test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let message = b"hello from fork exec\n";
    let mut target = vec![0xbf, 0x01, 0x00, 0x00, 0x00]; // mov edi, 1
    let message_operand = target.len() + 2;
    target.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, message
    target.push(0xba);
    target.extend_from_slice(&(message.len() as u32).to_le_bytes()); // mov edx, len
    target.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05]); // write
    target.extend_from_slice(&[
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b,
    ]); // exit_group(0); ud2
    let message_address = LOAD_ADDRESS + target.len() as u64;
    target[message_operand..message_operand + 8].copy_from_slice(&message_address.to_le_bytes());
    target.extend_from_slice(message);
    let executable = TestExecutable::new(&static_elf(&target));
    let path = executable.0.to_str().unwrap().as_bytes();

    let mut root = vec![
        0x49, 0xc7, 0xc4, 0x78, 0x56, 0x34, 0x12, // mov r12, 0x12345678
        0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0x66, 0x0f, 0x6e, 0xc0, // movd xmm0, eax
        0xb8, 0x39, 0x00, 0x00, 0x00, // mov eax, SYS_fork
        0x0f, 0x05, // syscall
        0x85, 0xc0, // test eax, eax
        0x74, 0x00, // jz child
    ];
    let child_jump = root.len() - 1;
    root.extend_from_slice(&[
        0x89, 0xc7, // mov edi, eax
        0x48, 0x83, 0xec, 0x10, // sub rsp, 16
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0x31, 0xd2, // xor edx, edx
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0x3d, 0x00, 0x00, 0x00, // mov eax, SYS_wait4
        0x0f, 0x05, // syscall
        0x8b, 0x3c, 0x24, // mov edi, dword ptr [rsp]
        0xc1, 0xef, 0x08, // shr edi, 8
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ]);
    let child_offset = root.len();
    let displacement = child_offset as isize - (child_jump + 1) as isize;
    root[child_jump] = i8::try_from(displacement).unwrap() as u8;

    root.extend_from_slice(&[
        0x49, 0x81, 0xfc, 0x78, 0x56, 0x34, 0x12, // cmp r12, 0x12345678
        0x74, 0x0e, // je callee_saved_ok
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
        0x66, 0x0f, 0x7e, 0xc0, // movd eax, xmm0
        0x3d, 0x78, 0x56, 0x34, 0x12, // cmp eax, 0x12345678
        0x74, 0x0e, // je fpu_ok
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2b, 0x00, 0x00, 0x00, // mov edi, 43
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
    ]);

    let path_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdi, path
    let argv_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, argv
    let envp_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xba, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdx, envp
    root.extend_from_slice(&[
        0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, // execve
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0xbf, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x0f,
        0x0b, // exit_group(42); ud2
    ]);

    let path_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(path);
    root.push(0);
    while !root.len().is_multiple_of(8) {
        root.push(0);
    }
    let argv_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&path_address.to_le_bytes());
    root.extend_from_slice(&0_u64.to_le_bytes());
    let envp_address = LOAD_ADDRESS + root.len() as u64;
    root.extend_from_slice(&0_u64.to_le_bytes());
    root[path_operand..path_operand + 8].copy_from_slice(&path_address.to_le_bytes());
    root[argv_operand..argv_operand + 8].copy_from_slice(&argv_address.to_le_bytes());
    root[envp_operand..envp_operand + 8].copy_from_slice(&envp_address.to_le_bytes());

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&root), "/bin/fork-exec-test")
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();

    assert_eq!(code, 0);
    assert_eq!(stdout, message);
    assert!(stderr.is_empty());

    let mut tool_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    tool_backend
        .install_static_elf(&static_elf(&root), "/bin/fork-exec-test")
        .unwrap();
    let (_, code, stdout, stderr) =
        futures::executor::block_on(tool_backend.run_static_elf_with_tool::<StraceTool>((), true))
            .unwrap();

    assert_eq!(code, 0);
    assert_eq!(stdout, message);
    assert!(stderr.is_empty());
}

#[test]
fn static_elf_clone_tid_side_effects_reach_guest_memory() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM clone TID test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    fn append_exit(code: &mut Vec<u8>, status: u32) {
        code.extend_from_slice(&[0xb8, 0xe7, 0x00, 0x00, 0x00]);
        code.push(0xbf);
        code.extend_from_slice(&status.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    }

    fn patch_jump(code: &mut [u8], operand: usize, target: usize) {
        let displacement = i32::try_from(target as isize - (operand + 4) as isize).unwrap();
        code[operand..operand + 4].copy_from_slice(&displacement.to_le_bytes());
    }

    const PARENT_TID: u64 = LOAD_ADDRESS + 0x1800;
    const CHILD_TID: u64 = LOAD_ADDRESS + 0x1808;
    const REPLACEMENT_CLEAR_TID: u64 = LOAD_ADDRESS + 0x1810;
    const INVALID_TID: u64 = MEMORY_SIZE as u64 - 1;
    let flags = libc::SIGCHLD as u32
        | libc::CLONE_PARENT_SETTID as u32
        | libc::CLONE_CHILD_SETTID as u32
        | libc::CLONE_CHILD_CLEARTID as u32;

    let mut code = Vec::new();
    code.extend_from_slice(&[0xb8, 0x38, 0x00, 0x00, 0x00]); // mov eax, SYS_clone
    code.push(0xbf); // mov edi, flags
    code.extend_from_slice(&flags.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xf6]); // xor esi, esi
    code.extend_from_slice(&[0x48, 0xba]); // movabs rdx, parent_tid
    code.extend_from_slice(&PARENT_TID.to_le_bytes());
    code.extend_from_slice(&[0x49, 0xba]); // movabs r10, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x85, 0xc0, 0x0f, 0x84, 0x00, 0x00, 0x00, 0x00]); // syscall; jz child
    let first_child_jump = code.len() - 4;

    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, parent_tid
    code.extend_from_slice(&PARENT_TID.to_le_bytes());
    code.extend_from_slice(&[0x39, 0x01, 0x74, 0x0e]); // cmp [rcx], eax; je parent_tid_ok
    append_exit(&mut code, 61);
    code.extend_from_slice(&[
        0x89, 0xc7, // mov edi, eax
        0x48, 0x83, 0xec, 0x10, // sub rsp, 16
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0x31, 0xd2, // xor edx, edx
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0x3d, 0x00, 0x00, 0x00, // mov eax, SYS_wait4
        0x0f, 0x05, // syscall
        0x83, 0x3c, 0x24, 0x00, // cmp dword ptr [rsp], 0
        0x74, 0x0e, // je first_child_ok
    ]);
    append_exit(&mut code, 64);

    // A second clone proves invalid TID stores do not abort child creation.
    code.extend_from_slice(&[0xb8, 0x38, 0x00, 0x00, 0x00]);
    code.push(0xbf);
    code.extend_from_slice(&flags.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xf6]); // xor esi, esi
    code.extend_from_slice(&[0x48, 0xba]); // movabs rdx, invalid parent_tid
    code.extend_from_slice(&INVALID_TID.to_le_bytes());
    code.extend_from_slice(&[0x49, 0xba]); // movabs r10, invalid child_tid
    code.extend_from_slice(&INVALID_TID.to_le_bytes());
    code.extend_from_slice(&[
        0x0f, 0x05, // syscall
        0x85, 0xc0, // test eax, eax
        0x79, 0x0e, // jns clone_returned_pid_or_child
    ]);
    append_exit(&mut code, 65);
    code.extend_from_slice(&[0x0f, 0x84, 0x00, 0x00, 0x00, 0x00]); // jz child
    let invalid_child_jump = code.len() - 4;
    code.extend_from_slice(&[
        0x89, 0xc7, // mov edi, eax
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0x31, 0xd2, // xor edx, edx
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0x3d, 0x00, 0x00, 0x00, // mov eax, SYS_wait4
        0x0f, 0x05, // syscall
        0x39, 0xf8, // cmp eax, edi
        0x74, 0x0e, // je waited_for_second_child
    ]);
    append_exit(&mut code, 66);
    code.extend_from_slice(&[
        0x8b, 0x3c, 0x24, // mov edi, dword ptr [rsp]
        0xc1, 0xef, 0x08, // shr edi, 8
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
    ]);

    let first_child = code.len();
    patch_jump(&mut code, first_child_jump, first_child);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[0x83, 0x39, 0x02, 0x74, 0x0e]); // cmp [rcx], 2; je
    append_exit(&mut code, 62);
    code.extend_from_slice(&[0xb8, 0xda, 0x00, 0x00, 0x00]); // set_tid_address
    code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, replacement pointer
    code.extend_from_slice(&REPLACEMENT_CLEAR_TID.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05, 0x83, 0xf8, 0x02, 0x74, 0x0e]); // syscall; cmp eax, 2; je
    append_exit(&mut code, 63);
    append_exit(&mut code, 0);

    let invalid_store_child = code.len();
    patch_jump(&mut code, invalid_child_jump, invalid_store_child);
    append_exit(&mut code, 0);

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/clone-tid-test")
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!(code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn real_bash_redirects_builtin_output_through_f_dupfd() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM Bash redirection test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let root = TestDirectory::new();
    let (stdout, stderr) = run_host_program_captured(
        "/bin/bash",
        &[
            "bash",
            "--norc",
            "-c",
            "printf redirected > output; printf visible",
        ],
        &root.0,
    );
    assert_eq!(stdout, b"visible");
    assert!(stderr.is_empty());
    assert_eq!(std::fs::read(root.0.join("output")).unwrap(), b"redirected");
}

#[test]
fn real_bash_small_pipeline_uses_legacy_process_clone_tid_flags() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM Bash pipeline test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let root = TestDirectory::new();
    // The child runs to completion before the parent resumes, so this covers a
    // bounded pipeline without claiming concurrent producer/consumer support.
    let (stdout, stderr) = run_host_program_captured(
        "/bin/bash",
        &["bash", "--norc", "-c", "printf abc | /usr/bin/wc -c"],
        &root.0,
    );
    assert_eq!(stdout, b"3\n");
    assert!(
        stderr.is_empty(),
        "unexpected Bash stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
}

#[test]
fn real_coreutils_complete_file_mutation_workflow() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM coreutils test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let root = TestDirectory::new();
    std::fs::write(root.0.join("source"), b"payload\n").unwrap();

    run_host_program("/bin/mkdir", &["mkdir", "directory"], &root.0);
    run_host_program("/usr/bin/touch", &["touch", "touched"], &root.0);
    run_host_program("/bin/chmod", &["chmod", "600", "touched"], &root.0);
    run_host_program("/bin/ln", &["ln", "source", "hard-link"], &root.0);
    run_host_program("/bin/ln", &["ln", "-s", "source", "symbolic-link"], &root.0);
    run_host_program("/bin/mv", &["mv", "hard-link", "renamed"], &root.0);
    run_host_program("/usr/bin/mkfifo", &["mkfifo", "fifo"], &root.0);
    run_host_program(
        "/usr/bin/install",
        &["install", "-m", "700", "source", "installed"],
        &root.0,
    );
    run_host_program("/bin/rm", &["rm", "renamed"], &root.0);

    assert!(root.0.join("directory").is_dir());
    assert_eq!(std::fs::read(root.0.join("source")).unwrap(), b"payload\n");
    assert!(root.0.join("touched").is_file());
    assert_eq!(
        std::fs::read_link(root.0.join("symbolic-link")).unwrap(),
        std::path::Path::new("source")
    );
    assert!(
        std::fs::symlink_metadata(root.0.join("fifo"))
            .unwrap()
            .file_type()
            .is_fifo()
    );
    assert_eq!(
        std::fs::read(root.0.join("installed")).unwrap(),
        b"payload\n"
    );
    assert!(!root.0.join("renamed").exists());
}

#[test]
fn static_elf_executes_syscall_and_exits() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM static ELF test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();

    backend
        .memory_mut()
        .write(LOAD_ADDRESS + 0x1000, &[0xff])
        .unwrap();

    // Check BSS and argc, then require deterministic getpid == 1 and preserved
    // RBX. Any loader or SYSCALL return-state error takes the exit_group(42)
    // path rather than producing a false pass.
    let code = [
        0x48, 0xb8, 0x00, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x201000
        0x80, 0x38, 0x00, // cmp byte ptr [rax], 0
        0x75, 0x2d, // jne failure
        0x48, 0x83, 0x3c, 0x24, 0x01, // cmp qword ptr [rsp], 1
        0x75, 0x26, // jne failure
        0xbb, 0x78, 0x56, 0x34, 0x12, // mov ebx, 0x12345678
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall
        0x48, 0x83, 0xf8, 0x01, // cmp rax, 1
        0x75, 0x14, // jne failure
        0x48, 0x81, 0xfb, 0x78, 0x56, 0x34, 0x12, // cmp rbx, 0x12345678
        0x75, 0x0b, // jne failure
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
        0xb8, 0xe7, 0x00, 0x00, 0x00, // failure: mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    backend
        .install_static_elf(&static_elf(&code), "/bin/true")
        .unwrap();

    assert_eq!(backend.run_static_elf().unwrap(), 0);
}

#[test]
fn static_elf_receives_argv_and_envp() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM argv/envp test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    // exit_group(42): the failure path taken by every self-check below. Exactly
    // 12 bytes, so each conditional jump that skips it uses rel8 = 0x0c.
    const FAIL: [u8; 12] = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, // syscall
    ];

    // The guest verifies the System V initial stack that the loader built for
    // argv = ["prog", "second"], envp = ["FOO=bar"]:
    //   [rsp+0]=argc [rsp+8]=argv0 [rsp+16]=argv1 [rsp+24]=NULL
    //   [rsp+32]=envp0 [rsp+40]=NULL
    // Any mismatch takes exit_group(42); success prints and exit_group(0).
    let message = b"hello from kvm m1\n";
    let mut code: Vec<u8> = Vec::new();
    // argc == 2
    code.extend_from_slice(&[0x48, 0x83, 0x3c, 0x24, 0x02, 0x74, 0x0c]); // cmp qword[rsp],2; je +12
    code.extend_from_slice(&FAIL);
    // argv[1] != 0
    code.extend_from_slice(&[0x48, 0x8b, 0x44, 0x24, 0x10, 0x48, 0x85, 0xc0, 0x75, 0x0c]); // mov rax,[rsp+16]; test; jne +12
    code.extend_from_slice(&FAIL);
    // envp[0] != 0
    code.extend_from_slice(&[0x48, 0x8b, 0x44, 0x24, 0x20, 0x48, 0x85, 0xc0, 0x75, 0x0c]); // mov rax,[rsp+32]; test; jne +12
    code.extend_from_slice(&FAIL);
    // envp[1] == 0 (single environment entry, then the NULL terminator)
    code.extend_from_slice(&[0x48, 0x8b, 0x44, 0x24, 0x28, 0x48, 0x85, 0xc0, 0x74, 0x0c]); // mov rax,[rsp+40]; test; je +12
    code.extend_from_slice(&FAIL);
    // write(1, message, message.len())
    code.extend_from_slice(&[0xbf, 0x01, 0x00, 0x00, 0x00]); // mov edi, 1
    let movabs_operand = code.len() + 2;
    code.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, <message vaddr>
    code.push(0xba);
    code.extend_from_slice(&(message.len() as u32).to_le_bytes()); // mov edx, len
    code.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05]); // mov eax,SYS_write; syscall
    // exit_group(0)
    code.extend_from_slice(&[
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b,
    ]); // mov eax,231; xor edi,edi; syscall; ud2
    let message_offset = code.len();
    code.extend_from_slice(message);
    let message_vaddr = LOAD_ADDRESS + message_offset as u64;
    code[movabs_operand..movabs_operand + 8].copy_from_slice(&message_vaddr.to_le_bytes());

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_args(&static_elf(&code), &["prog", "second"], &["FOO=bar"])
        .unwrap();

    assert_eq!(backend.run_static_elf().unwrap(), 0);
}

#[test]
fn tool_receives_post_exec_with_guest_auxv() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM post-exec test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let code = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_args(&static_elf(&code), &["prog"], &[])
        .unwrap();

    let (log, exit_code, _, _) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<PostExecTool>((), true))
            .unwrap();

    assert_eq!(exit_code, 0);
    let address = log
        .at_random()
        .expect("post-exec hook did not observe AT_RANDOM");
    let mut random = [0; 16];
    backend.memory().read(address as u64, &mut random).unwrap();
    assert_eq!(random, POST_EXEC_RANDOM);
}

#[test]
fn post_exec_failure_runs_tool_exit_lifecycle() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM post-exec failure test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    POST_EXEC_FAILURE_EXITED.store(false, Ordering::SeqCst);
    let code = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b,
    ];
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_args(&static_elf(&code), &["prog"], &[])
        .unwrap();

    let error = futures::executor::block_on(
        backend.run_static_elf_with_tool::<FailingPostExecTool>((), true),
    )
    .unwrap_err();

    assert!(error.to_string().contains("post-exec hook failed"));
    assert!(POST_EXEC_FAILURE_EXITED.load(Ordering::SeqCst));
}

#[test]
fn strace_tool_logs_syscalls_from_static_elf() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM strace-ELF test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    // A static ELF guest that issues getpid, write(1, "hi\n", 3), exit_group(0)
    // via real SYSCALL instructions. Each traps through the ring0 trampoline and
    // must be observed by StraceTool, whose tail_inject is serviced by the ELF
    // guest kernel (so getpid returns 1, the write prints, and exit_group ends
    // the run).
    let message = b"hi\n";
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05]); // mov eax,SYS_getpid; syscall
    code.extend_from_slice(&[0xbf, 0x01, 0x00, 0x00, 0x00]); // mov edi, 1
    let movabs_operand = code.len() + 2;
    code.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, <message vaddr>
    code.push(0xba);
    code.extend_from_slice(&(message.len() as u32).to_le_bytes()); // mov edx, len
    code.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05]); // mov eax,SYS_write; syscall
    code.extend_from_slice(&[
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b,
    ]); // mov eax,SYS_exit_group; xor edi,edi; syscall; ud2
    let message_offset = code.len();
    code.extend_from_slice(message);
    let message_vaddr = LOAD_ADDRESS + message_offset as u64;
    code[movabs_operand..movabs_operand + 8].copy_from_slice(&message_vaddr.to_le_bytes());

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf_with_args(&static_elf(&code), &["prog"], &[])
        .unwrap();

    let (log, exit_code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true))
            .unwrap();

    assert_eq!(exit_code, 0);
    assert_eq!(stdout, b"hi\n");
    assert!(stderr.is_empty());
    assert_eq!(
        log.syscalls(),
        vec![
            "getpid".to_string(),
            "write".to_string(),
            "exit_group".to_string(),
        ],
    );
}

fn static_elf(code: &[u8]) -> Vec<u8> {
    let mut image = vec![0; CODE_OFFSET + code.len()];

    image[..4].copy_from_slice(b"\x7fELF");
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    put_u16(&mut image, 16, 2);
    put_u16(&mut image, 18, 62);
    put_u32(&mut image, 20, 1);
    put_u64(&mut image, 24, LOAD_ADDRESS);
    put_u64(&mut image, 32, 64);
    put_u16(&mut image, 52, 64);
    put_u16(&mut image, 54, 56);
    put_u16(&mut image, 56, 1);

    put_u32(&mut image, 64, 1);
    put_u32(&mut image, 68, 5);
    put_u64(&mut image, 72, CODE_OFFSET as u64);
    put_u64(&mut image, 80, LOAD_ADDRESS);
    put_u64(&mut image, 88, LOAD_ADDRESS);
    put_u64(&mut image, 96, code.len() as u64);
    put_u64(&mut image, 104, 0x2000);
    put_u64(&mut image, 112, 0x1000);
    image[CODE_OFFSET..].copy_from_slice(code);
    image
}

fn put_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(image: &mut [u8], offset: usize, value: u64) {
    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
