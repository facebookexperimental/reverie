/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(target_arch = "x86_64")]

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
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
use reverie_kvm::KvmBackend;
use reverie_kvm::StraceTool;

const MEMORY_SIZE: usize = 16 * 1024 * 1024;
const LOAD_ADDRESS: u64 = 0x20_0000;
const CODE_OFFSET: usize = 0x1000;
const POST_EXEC_RANDOM: [u8; 16] = *b"kvm-post-exec-ok";
static POST_EXEC_FAILURE_EXITED: AtomicBool = AtomicBool::new(false);

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
