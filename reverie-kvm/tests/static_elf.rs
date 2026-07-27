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
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::CArrayPtr;
use reverie::syscalls::CStrPtr;
use reverie::syscalls::Errno;
use reverie::syscalls::Execve;
use reverie::syscalls::Fork;
use reverie::syscalls::FromToRaw;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::PathPtr;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;
use reverie_kvm::CounterTool;
use reverie_kvm::Error;
use reverie_kvm::HierarchicalCounterTool;
use reverie_kvm::HierarchicalTotals;
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
        .install_static_elf_with_context(&image, argv, &["PATH=/usr/bin:/bin"], cwd)
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

fn set_interrupt_signal_blocked(blocked: bool) -> bool {
    // SAFETY: set and previous are initialized before libc reads or writes them.
    unsafe {
        let mut set = std::mem::zeroed::<libc::sigset_t>();
        let mut previous = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGURG);
        let how = if blocked {
            libc::SIG_BLOCK
        } else {
            libc::SIG_UNBLOCK
        };
        assert_eq!(libc::pthread_sigmask(how, &set, &mut previous), 0);
        libc::sigismember(&previous, libc::SIGURG) == 1
    }
}

#[derive(Default)]
struct PostExecLog {
    at_random: Mutex<Option<usize>>,
    calls: AtomicU64,
}

impl PostExecLog {
    fn at_random(&self) -> Option<usize> {
        *self.at_random.lock().expect("post-exec log lock poisoned")
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[reverie::global_tool]
impl GlobalTool for PostExecLog {
    type Request = usize;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, at_random: usize) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.at_random.lock().expect("post-exec log lock poisoned") = Some(at_random);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PostExecTool;

#[reverie::tool]
impl Tool for PostExecTool {
    type GlobalState = PostExecLog;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::execve]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        guest.tail_inject(syscall).await
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        let auxv = guest.auxv();
        let address = auxv.at_random().ok_or(Errno::EINVAL)?;
        guest.send_rpc(address.as_raw()).await;
        // This lifecycle hook runs before the ELF entry point, matching execve.
        let address = unsafe { address.into_mut() };
        guest.memory().write_value(address, &POST_EXEC_RANDOM)
    }
}

#[derive(Default)]
struct StartExecLog {
    post_exec_calls: AtomicU64,
}

impl StartExecLog {
    fn post_exec_calls(&self) -> u64 {
        self.post_exec_calls.load(Ordering::SeqCst)
    }
}

#[reverie::global_tool]
impl GlobalTool for StartExecLog {
    type Request = ();
    type Response = ();
    type Config = (usize, usize, usize);

    async fn receive_rpc(&self, _from: Pid, (): ()) {
        self.post_exec_calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct StartExecTool;

#[reverie::tool]
impl Tool for StartExecTool {
    type GlobalState = StartExecLog;
    type ThreadState = ();

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        let (path, argv, envp) = *guest.config();
        let execve = Execve::new()
            .with_path(PathPtr::from_ptr(path as *const libc::c_char))
            .with_argv(Option::<CArrayPtr<CStrPtr>>::from_raw(argv))
            .with_envp(Option::<CArrayPtr<CStrPtr>>::from_raw(envp));
        guest.inject(execve).await?;
        Err(Errno::EINVAL.into())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        guest.send_rpc(()).await;
        Ok(())
    }
}

#[derive(Default)]
struct RpcRoundTripLog {
    response_base: u64,
    requests: Mutex<Vec<(Pid, u64)>>,
}

impl RpcRoundTripLog {
    fn requests(&self) -> Vec<(Pid, u64)> {
        self.requests
            .lock()
            .expect("RPC round-trip log lock poisoned")
            .clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for RpcRoundTripLog {
    type Request = u64;
    type Response = u64;
    type Config = u64;

    async fn init_global_state(response_base: &u64) -> Self {
        Self {
            response_base: *response_base,
            requests: Mutex::default(),
        }
    }

    async fn receive_rpc(&self, from: Pid, ordinal: u64) -> u64 {
        self.requests
            .lock()
            .expect("RPC round-trip log lock poisoned")
            .push((from, ordinal));
        self.response_base + ordinal
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RpcRoundTripTool;

#[reverie::tool]
impl Tool for RpcRoundTripTool {
    type GlobalState = RpcRoundTripLog;
    type ThreadState = u64;

    fn subscriptions(_config: &u64) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscall(Sysno::getpid);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        assert!(matches!(syscall, Syscall::Getpid(_)));
        let ordinal = {
            let ordinal = guest.thread_state_mut();
            *ordinal += 1;
            *ordinal
        };
        Ok(guest.send_rpc(ordinal).await as i64)
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        global: &G,
        thread_state: Self::ThreadState,
        _status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        let ordinal = thread_state + 1;
        assert_eq!(global.send_rpc(ordinal).await, *global.config() + ordinal);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DoubleForkTool;

#[reverie::tool]
impl Tool for DoubleForkTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscalls([Sysno::fork]);
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let Syscall::Fork(fork) = syscall else {
            panic!("expected fork, got {syscall:?}");
        };
        let first = guest.inject(fork).await?;
        let second = guest.inject(Fork::new()).await?;
        assert!(first > 0);
        assert!(second > first);
        Ok(first)
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
fn static_elf_cannot_copy_supervisor_bootstrap_memory() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM bootstrap access test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let code = [
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0xbe, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
        0xba, 0x10, 0x00, 0x00, 0x00, // mov edx, 16
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, SYS_write
        0x0f, 0x05, // syscall
        0x48, 0x83, 0xf8, 0xf2, // cmp rax, -EFAULT
        0x74, 0x0e, // je success
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
    ];

    for with_tool in [false, true] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&code), "/bin/bootstrap-access-test")
            .unwrap();
        let (exit_code, stdout, stderr) = if with_tool {
            let (_, exit_code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (exit_code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(exit_code, 0, "with_tool={with_tool}");
        assert!(stdout.is_empty(), "with_tool={with_tool}");
        assert!(stderr.is_empty(), "with_tool={with_tool}");
    }
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
fn static_elf_self_abort_terminates_instead_of_faulting() {
    // Regression: glibc abort() writes its diagnostic, then raises SIGABRT via
    // tgkill(pid, tid, SIGABRT). Previously SIGABRT was unhandled (ENOSYS), so
    // abort() fell through to its "unreachable" hlt trap and the VM reported a
    // spurious #GP (exception vector 13). A self-directed fatal signal must now
    // terminate the process with the conventional 128 + signo status while
    // preserving output emitted before the signal.
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM self-abort test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let message = b"before abort\n";
    // write(1, message, len)
    let mut code = vec![0xbf, 0x01, 0x00, 0x00, 0x00]; // mov edi, 1
    let message_operand = code.len() + 2;
    code.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, message
    code.push(0xba);
    code.extend_from_slice(&(message.len() as u32).to_le_bytes()); // mov edx, len
    code.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05]); // mov eax, SYS_write; syscall
    // pid = getpid(); tgkill(pid, pid, SIGABRT)
    code.extend_from_slice(&[
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall -> rax = pid
        0x89, 0xc7, // mov edi, eax  (tgid)
        0x89, 0xc6, // mov esi, eax  (tid)
        0xba, 0x06, 0x00, 0x00, 0x00, // mov edx, SIGABRT
        0xb8, 0xea, 0x00, 0x00, 0x00, // mov eax, SYS_tgkill
        0x0f, 0x05, // syscall -> must terminate here
        0x0f, 0x0b, // ud2 (only reached if the signal did not terminate us)
    ]);
    let message_address = LOAD_ADDRESS + code.len() as u64;
    code[message_operand..message_operand + 8].copy_from_slice(&message_address.to_le_bytes());
    code.extend_from_slice(message);

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/self-abort")
        .unwrap();
    let (code_result, stdout, stderr) = backend.run_static_elf_captured().unwrap();

    // 128 + SIGABRT(6) == 134, matching the shell/native convention.
    assert_eq!(code_result, 128 + libc::SIGABRT);
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
fn static_elf_runs_glibc_clone3_thread_and_restores_parent_state() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM clone3 thread test: cannot open /dev/kvm: {error}");
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
    const CHILD_RESULT: u64 = LOAD_ADDRESS + 0x1810;
    const CHILD_FS: u64 = LOAD_ADDRESS + 0x1818;
    const CHILD_RSP: u64 = LOAD_ADDRESS + 0x1820;
    const TLS: u64 = LOAD_ADDRESS + 0x1880;
    const CHILD_STACK: u64 = LOAD_ADDRESS + 0x1900;
    const CHILD_STACK_SIZE: u64 = 0x600;
    const CHILD_STACK_TOP: u64 = CHILD_STACK + CHILD_STACK_SIZE;
    let flags = libc::CLONE_VM as u64
        | libc::CLONE_FS as u64
        | libc::CLONE_FILES as u64
        | libc::CLONE_SIGHAND as u64
        | libc::CLONE_THREAD as u64
        | libc::CLONE_SYSVSEM as u64
        | libc::CLONE_SETTLS as u64
        | libc::CLONE_PARENT_SETTID as u64
        | libc::CLONE_CHILD_CLEARTID as u64;

    let mut code = vec![
        0x49, 0x89, 0xe4, // mov r12, rsp
        0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0x66, 0x0f, 0x6e, 0xc0, // movd xmm0, eax
    ];
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[0xc7, 0x01, 0xff, 0xff, 0xff, 0x7f]); // mov [rcx], sentinel
    code.extend_from_slice(&[0xb8, 0xb3, 0x01, 0x00, 0x00]); // mov eax, SYS_clone3
    let clone_args_operand = code.len() + 2;
    code.extend_from_slice(&[0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdi, clone_args
    code.extend_from_slice(&[0xbe, 0x58, 0x00, 0x00, 0x00]); // mov esi, sizeof(clone_args)
    code.extend_from_slice(&[0x0f, 0x05, 0x85, 0xc0, 0x0f, 0x84, 0, 0, 0, 0]); // syscall; jz child
    let child_jump = code.len() - 4;

    code.extend_from_slice(&[0x4c, 0x39, 0xe4, 0x74, 0x0e]); // cmp rsp, r12; je
    append_exit(&mut code, 81);
    code.extend_from_slice(&[0x41, 0x89, 0xc5]); // mov r13d, eax
    code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[
        0xbe, 0x00, 0x00, 0x00, 0x00, // mov esi, FUTEX_WAIT
        0x44, 0x89, 0xea, // mov edx, r13d
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, SYS_futex
        0x0f, 0x05, // syscall
        0x83, 0x3f, 0x00, // cmp dword ptr [rdi], 0
        0x75, 0xe9, // jne FUTEX_WAIT
        0x44, 0x89, 0xe8, // mov eax, r13d
    ]);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, parent_tid
    code.extend_from_slice(&PARENT_TID.to_le_bytes());
    code.extend_from_slice(&[0x39, 0x01, 0x74, 0x0e]); // cmp [rcx], eax; je
    append_exit(&mut code, 82);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_result
    code.extend_from_slice(&CHILD_RESULT.to_le_bytes());
    code.extend_from_slice(&[0x39, 0x01, 0x74, 0x0e]); // cmp [rcx], eax; je
    append_exit(&mut code, 83);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[0x83, 0x39, 0x00, 0x74, 0x0e]); // cmp dword ptr [rcx], 0; je
    append_exit(&mut code, 84);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_fs
    code.extend_from_slice(&CHILD_FS.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xba]); // movabs rdx, tls
    code.extend_from_slice(&TLS.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x39, 0x11, 0x74, 0x0e]); // cmp [rcx], rdx; je
    append_exit(&mut code, 85);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_rsp
    code.extend_from_slice(&CHILD_RSP.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xba]); // movabs rdx, child_stack_top
    code.extend_from_slice(&CHILD_STACK_TOP.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x39, 0x11, 0x74, 0x0e]); // cmp [rcx], rdx; je
    append_exit(&mut code, 86);
    code.extend_from_slice(&[
        0x66, 0x0f, 0x7e, 0xc0, // movd eax, xmm0
        0x3d, 0x78, 0x56, 0x34, 0x12, // cmp eax, 0x12345678
        0x74, 0x0e, // je
    ]);
    append_exit(&mut code, 87);
    code.extend_from_slice(&[
        0xb8, 0xba, 0x00, 0x00, 0x00, // mov eax, SYS_gettid
        0x0f, 0x05, // syscall
        0x83, 0xf8, 0x01, // cmp eax, 1
        0x74, 0x0e, // je
    ]);
    append_exit(&mut code, 88);
    append_exit(&mut code, 0);

    let child = code.len();
    patch_jump(&mut code, child_jump, child);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_rsp
    code.extend_from_slice(&CHILD_RSP.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0x21]); // mov [rcx], rsp
    code.extend_from_slice(&[0xb8, 0x9e, 0x00, 0x00, 0x00]); // mov eax, SYS_arch_prctl
    code.extend_from_slice(&[0xbf, 0x03, 0x10, 0x00, 0x00]); // mov edi, ARCH_GET_FS
    code.extend_from_slice(&[0x48, 0xbe]); // movabs rsi, child_fs
    code.extend_from_slice(&CHILD_FS.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05]); // syscall
    code.extend_from_slice(&[0xb8, 0xba, 0x00, 0x00, 0x00, 0x0f, 0x05]); // gettid
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_result
    code.extend_from_slice(&CHILD_RESULT.to_le_bytes());
    code.extend_from_slice(&[0x89, 0x01]); // mov [rcx], eax
    code.extend_from_slice(&[
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, SYS_exit
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ]);

    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let clone_args_address = LOAD_ADDRESS + code.len() as u64;
    code[clone_args_operand..clone_args_operand + 8]
        .copy_from_slice(&clone_args_address.to_le_bytes());
    let mut clone_args = [0_u8; 88];
    clone_args[0..8].copy_from_slice(&flags.to_le_bytes());
    // Linux ignores pidfd without CLONE_PIDFD; glibc aliases this union slot.
    clone_args[8..16].copy_from_slice(&CHILD_TID.to_le_bytes());
    clone_args[16..24].copy_from_slice(&CHILD_TID.to_le_bytes());
    clone_args[24..32].copy_from_slice(&PARENT_TID.to_le_bytes());
    clone_args[40..48].copy_from_slice(&CHILD_STACK.to_le_bytes());
    clone_args[48..56].copy_from_slice(&CHILD_STACK_SIZE.to_le_bytes());
    clone_args[56..64].copy_from_slice(&TLS.to_le_bytes());
    code.extend_from_slice(&clone_args);

    for with_tool in [false, true] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&code), "/bin/clone3-thread-test")
            .unwrap();
        let (exit_code, stdout, stderr) = if with_tool {
            let (_, exit_code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (exit_code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(exit_code, 0, "with_tool={with_tool}");
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }
}

#[test]
fn worker_exit_group_terminates_the_root_with_its_status() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM worker exit_group test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    fn append_exit_group(code: &mut Vec<u8>, status: u32) {
        code.extend_from_slice(&[0xb8, 0xe7, 0x00, 0x00, 0x00]);
        code.push(0xbf);
        code.extend_from_slice(&status.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    }

    fn patch_jump(code: &mut [u8], operand: usize, target: usize) {
        let displacement = i32::try_from(target as isize - (operand + 4) as isize).unwrap();
        code[operand..operand + 4].copy_from_slice(&displacement.to_le_bytes());
    }

    const CHILD_TID: u64 = LOAD_ADDRESS + 0x1800;
    const CHILD_STACK: u64 = LOAD_ADDRESS + 0x1900;
    const CHILD_STACK_SIZE: u64 = 0x600;
    let flags = libc::CLONE_VM as u64
        | libc::CLONE_FS as u64
        | libc::CLONE_FILES as u64
        | libc::CLONE_SIGHAND as u64
        | libc::CLONE_THREAD as u64
        | libc::CLONE_CHILD_SETTID as u64
        | libc::CLONE_CHILD_CLEARTID as u64;

    let mut code = Vec::new();
    code.extend_from_slice(&[0xb8, 0xb3, 0x01, 0x00, 0x00]); // mov eax, SYS_clone3
    let clone_args_operand = code.len() + 2;
    code.extend_from_slice(&[0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdi, clone_args
    code.extend_from_slice(&[0xbe, 0x58, 0x00, 0x00, 0x00]); // mov esi, sizeof(clone_args)
    code.extend_from_slice(&[0x0f, 0x05, 0x85, 0xc0, 0x0f, 0x84, 0, 0, 0, 0]); // syscall; jz child
    let child_jump = code.len() - 4;

    code.extend_from_slice(&[0x41, 0x89, 0xc5]); // mov r13d, eax
    code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    let wait = code.len();
    code.extend_from_slice(&[
        0xbe, 0x00, 0x00, 0x00, 0x00, // mov esi, FUTEX_WAIT
        0x44, 0x89, 0xea, // mov edx, r13d
        0x45, 0x31, 0xd2, // xor r10d, r10d
        0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, SYS_futex
        0x0f, 0x05, // syscall
        0x83, 0x3f, 0x00, // cmp dword ptr [rdi], 0
        0x0f, 0x85, 0, 0, 0, 0, // jne wait
    ]);
    let wait_jump = code.len() - 4;
    patch_jump(&mut code, wait_jump, wait);
    append_exit_group(&mut code, 0);

    let child = code.len();
    patch_jump(&mut code, child_jump, child);
    append_exit_group(&mut code, 37);

    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let clone_args_address = LOAD_ADDRESS + code.len() as u64;
    code[clone_args_operand..clone_args_operand + 8]
        .copy_from_slice(&clone_args_address.to_le_bytes());
    let mut clone_args = [0_u8; 88];
    clone_args[0..8].copy_from_slice(&flags.to_le_bytes());
    clone_args[16..24].copy_from_slice(&CHILD_TID.to_le_bytes());
    clone_args[40..48].copy_from_slice(&CHILD_STACK.to_le_bytes());
    clone_args[48..56].copy_from_slice(&CHILD_STACK_SIZE.to_le_bytes());
    code.extend_from_slice(&clone_args);

    for with_tool in [false, true] {
        let was_blocked = set_interrupt_signal_blocked(true);
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&code), "/bin/worker-exit-group-test")
            .unwrap();
        let exit_code = if with_tool {
            let (_, exit_code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            assert!(stdout.is_empty());
            assert!(stderr.is_empty());
            exit_code
        } else {
            backend.run_static_elf().unwrap()
        };
        let mut child_tid = [0; std::mem::size_of::<i32>()];
        backend.memory().read(CHILD_TID, &mut child_tid).unwrap();
        let remained_blocked = set_interrupt_signal_blocked(was_blocked);
        assert!(remained_blocked, "with_tool={with_tool}");
        assert_eq!(exit_code, 37, "with_tool={with_tool}");
        assert_eq!(i32::from_le_bytes(child_tid), 0, "with_tool={with_tool}");
    }
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

    run_host_program("/bin/mkdir", &["mkdir", "-p", "directory/nested"], &root.0);
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
    run_host_program("/bin/rmdir", &["rmdir", "directory/nested"], &root.0);

    assert!(root.0.join("directory").is_dir());
    assert!(!root.0.join("directory/nested").exists());
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
    assert_eq!(log.calls(), 1);
    let address = log
        .at_random()
        .expect("post-exec hook did not observe AT_RANDOM");
    let mut random = [0; 16];
    backend.memory().read(address as u64, &mut random).unwrap();
    assert_eq!(random, POST_EXEC_RANDOM);
}

#[test]
fn tool_receives_post_exec_after_root_execve() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM post-exec replacement test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let target = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let executable = TestExecutable::new(&static_elf(&target));
    let path = executable.0.to_str().unwrap().as_bytes();

    let mut root = Vec::new();
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
        .install_static_elf(&static_elf(&root), "/bin/root-exec-test")
        .unwrap();

    let (log, exit_code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<PostExecTool>((), true))
            .unwrap();

    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(log.calls(), 2);
}

#[test]
fn tool_executes_from_thread_start_before_initial_entry() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM thread-start exec test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let target = [
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let executable = TestExecutable::new(&static_elf(&target));
    let path = executable.0.to_str().unwrap().as_bytes();

    let mut root = vec![
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x2a, 0x00, 0x00, 0x00, // mov edi, 42
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
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

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&root), "/bin/thread-start-exec-test")
        .unwrap();
    let config = (
        path_address as usize,
        argv_address as usize,
        envp_address as usize,
    );
    let (log, exit_code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<StartExecTool>(config, true),
    )
    .unwrap();

    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(log.post_exec_calls(), 1);
}

#[test]
fn regular_injected_forks_complete_before_return() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM regular fork injection test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let code = [
        0xb8, 0x39, 0x00, 0x00, 0x00, // mov eax, SYS_fork
        0x0f, 0x05, // syscall
        0x89, 0xc7, // mov edi, eax
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/double-injected-fork-test")
        .unwrap();

    let (_, exit_code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<DoubleForkTool>((), true))
            .unwrap();

    assert_eq!(exit_code, 2);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn malformed_exec_returns_enoexec_without_replacing_image() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM malformed exec test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let executable = TestExecutable::new(b"not an ELF image");
    let path = executable.0.to_str().unwrap().as_bytes();
    let mut root = Vec::new();
    let path_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdi, path
    let argv_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rsi, argv
    let envp_operand = root.len() + 2;
    root.extend_from_slice(&[0x48, 0xba, 0, 0, 0, 0, 0, 0, 0, 0]); // movabs rdx, envp
    root.extend_from_slice(&[
        0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, // execve
        0xf7, 0xd8, // neg eax
        0x89, 0xc7, // mov edi, eax
        0xb8, 0xe7, 0x00, 0x00, 0x00, 0x0f, 0x05, // exit_group(errno)
        0x0f, 0x0b, // ud2
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

    for with_tool in [false, true] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&root), "/bin/malformed-exec-test")
            .unwrap();
        let (exit_code, stdout, stderr) = if with_tool {
            let (_, exit_code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            (exit_code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(exit_code, libc::ENOEXEC, "with_tool={with_tool}");
        assert!(stdout.is_empty(), "with_tool={with_tool}");
        assert!(stderr.is_empty(), "with_tool={with_tool}");
    }
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

#[test]
fn tool_rpc_response_reaches_intercepted_static_elf_syscall() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM RPC round-trip test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    // Each getpid is intercepted instead of injected. The local tool advances
    // its ThreadState, sends the ordinal to GlobalState, and returns the typed
    // RPC response as the guest-visible syscall result. The exit hook then
    // sends a third typed RPC through the lifecycle GlobalRPC handle. Exit 1
    // if either guest-visible round trip produced an unexpected value.
    let code = [
        0x45, 0x31, 0xe4, // xor r12d, r12d
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall
        0x3d, 0xe9, 0x03, 0x00, 0x00, // cmp eax, 1001
        0x41, 0x0f, 0x95, 0xc4, // setne r12b
        0xb8, 0x27, 0x00, 0x00, 0x00, // mov eax, SYS_getpid
        0x0f, 0x05, // syscall
        0x3d, 0xea, 0x03, 0x00, 0x00, // cmp eax, 1002
        0x0f, 0x95, 0xc0, // setne al
        0x0f, 0xb6, 0xc0, // movzx eax, al
        0x41, 0x09, 0xc4, // or r12d, eax
        0x44, 0x89, 0xe7, // mov edi, r12d
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ];
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_static_elf(&static_elf(&code), "/bin/rpc-round-trip")
        .unwrap();

    let (log, exit_code, stdout, stderr) = futures::executor::block_on(
        backend.run_static_elf_with_tool::<RpcRoundTripTool>(1000, true),
    )
    .unwrap();

    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(
        log.requests(),
        vec![
            (Pid::from_raw(1), 1),
            (Pid::from_raw(1), 2),
            (Pid::from_raw(1), 3),
        ]
    );
}

#[test]
fn counter_tools_aggregate_intercepted_static_elf_syscalls() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM counter-ELF test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let code = [
        0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, // getpid
        0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, // getpid
        0xb8, 0xe7, 0x00, 0x00, 0x00, // exit_group
        0x31, 0xff, 0x0f, 0x05, // status 0; syscall
        0x0f, 0x0b, // ud2
    ];
    let image = static_elf(&code);

    let mut direct_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    direct_backend
        .install_static_elf(&image, "/bin/counter-rpc")
        .unwrap();
    let (counter, exit_code, stdout, stderr) = futures::executor::block_on(
        direct_backend.run_static_elf_with_tool::<CounterTool>((), true),
    )
    .unwrap();
    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(counter.total(), 3);

    let mut hierarchical_backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    hierarchical_backend
        .install_static_elf(&image, "/bin/hierarchical-counter-rpc")
        .unwrap();
    let (counter, exit_code, stdout, stderr) = futures::executor::block_on(
        hierarchical_backend.run_static_elf_with_tool::<HierarchicalCounterTool>((), true),
    )
    .unwrap();
    assert_eq!(exit_code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(
        counter.totals(),
        HierarchicalTotals {
            total_syscalls: 3,
            exited_procs: 1,
            exited_threads: 1,
        }
    );
}

#[test]
fn real_make_runs_a_shell_recipe_through_clone3_vfork() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM make test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }
    let root = TestDirectory::new();
    std::fs::write(
        root.0.join("Makefile"),
        "all: result.txt\nresult.txt:\n\tprintf 'make:42\\n' > result.txt\n",
    )
    .unwrap();
    run_host_program("/usr/bin/make", &["make", "-s"], &root.0);
    assert_eq!(
        std::fs::read(root.0.join("result.txt")).unwrap(),
        b"make:42\n"
    );
}

#[test]
fn real_gcc_compiles_an_object_through_child_processes() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM gcc test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }
    let root = TestDirectory::new();
    std::fs::write(
        root.0.join("fixture.c"),
        b"int hermit_compat(void) { return 42; }\n",
    )
    .unwrap();
    run_host_program(
        "/usr/bin/gcc",
        &[
            "gcc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-fno-ident",
            "-frandom-seed=hermit-gcc",
            "-c",
            "fixture.c",
            "-o",
            "fixture.o",
        ],
        &root.0,
    );
    assert!(root.0.join("fixture.o").is_file());
}

#[test]
fn real_patch_applies_exact_hunk_with_absent_xattrs() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM patch test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let root = TestDirectory::new();
    std::fs::write(root.0.join("file"), b"old\n").unwrap();
    std::fs::write(
        root.0.join("change.patch"),
        b"--- file\n+++ file\n@@ -1 +1 @@\n-old\n+new\n",
    )
    .unwrap();
    let (stdout, stderr) = run_host_program_captured(
        "/usr/bin/patch",
        &["patch", "--quiet", "--input=change.patch", "file"],
        &root.0,
    );
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert_eq!(std::fs::read(root.0.join("file")).unwrap(), b"new\n");
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
