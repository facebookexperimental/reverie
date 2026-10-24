use super::*;

#[derive(Debug, Default)]
struct CaptureIdentityTool;

#[reverie::tool]
impl Tool for CaptureIdentityTool {
    type GlobalState = ();
    type ThreadState = ();
}

fn capture_identity_program() -> Vec<u8> {
    let mut code = vec![
        0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00, // sub rsp, 512
        0x49, 0x89, 0xe4, // mov r12, rsp: stdout stat
        0x4c, 0x8d, 0xac, 0x24, 0x90, 0x00, 0x00, 0x00, // lea r13,[rsp+144]: pipe stat
        0x4c, 0x8d, 0xb4, 0x24, 0x20, 0x01, 0x00, 0x00, // lea r14,[rsp+288]: pipe fds
    ];
    let mut failures = Vec::new();
    fn syscall_zero(code: &mut Vec<u8>, failures: &mut Vec<usize>, number: u32) {
        code.push(0xb8);
        code.extend_from_slice(&number.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x48, 0x85, 0xc0]); // syscall; test rax,rax
        append_jne_failure(code, failures);
    }
    code.extend_from_slice(&[0xbf, 1, 0, 0, 0, 0x4c, 0x89, 0xe6]); // fd1; rsi=r12
    syscall_zero(&mut code, &mut failures, libc::SYS_fstat as u32);
    code.extend_from_slice(&[0x4c, 0x89, 0xf7, 0x31, 0xf6]); // rdi=r14; flags=0
    syscall_zero(&mut code, &mut failures, libc::SYS_pipe2 as u32);
    code.extend_from_slice(&[0x41, 0x8b, 0x3e, 0x4c, 0x89, 0xee]); // edi=[r14]; rsi=r13
    syscall_zero(&mut code, &mut failures, libc::SYS_fstat as u32);
    code.extend_from_slice(&[0x49, 0x8b, 0x04, 0x24, 0x49, 0x3b, 0x45, 0x00]); // cmp stdout.dev,pipe.dev
    append_jne_failure(&mut code, &mut failures);
    code.extend_from_slice(&[0x49, 0x8b, 0x44, 0x24, 0x08, 0x49, 0x3b, 0x45, 0x08]); // cmp inodes
    code.extend_from_slice(&[0x0f, 0x84]); // je failure: distinct live objects
    failures.push(code.len());
    code.extend_from_slice(&0_i32.to_le_bytes());
    for load in [
        &[0x41, 0x8b, 0x44, 0x24, 0x18][..],
        &[0x41, 0x8b, 0x45, 0x18][..],
    ] {
        code.extend_from_slice(load); // eax=st_mode
        code.push(0x25); // and eax,S_IFMT
        code.extend_from_slice(&libc::S_IFMT.to_le_bytes());
        code.push(0x3d); // cmp eax,S_IFIFO
        code.extend_from_slice(&libc::S_IFIFO.to_le_bytes());
        append_jne_failure(&mut code, &mut failures);
    }
    code.extend_from_slice(&[0x41, 0x8b, 0x3e]);
    syscall_zero(&mut code, &mut failures, libc::SYS_close as u32);
    code.extend_from_slice(&[0x41, 0x8b, 0x7e, 0x04]);
    syscall_zero(&mut code, &mut failures, libc::SYS_close as u32);
    let message = b"capture-pipe-ok\n";
    code.extend_from_slice(&[0xbf, 1, 0, 0, 0, 0x48, 0xbe]);
    let message_operand = code.len();
    code.extend_from_slice(&0_u64.to_le_bytes());
    code.push(0xba);
    code.extend_from_slice(&(message.len() as u32).to_le_bytes());
    code.extend_from_slice(&[0xb8, 1, 0, 0, 0, 0x0f, 0x05, 0x48, 0x3d]);
    code.extend_from_slice(&(message.len() as u32).to_le_bytes());
    append_jne_failure(&mut code, &mut failures);
    append_stats_exit(&mut code, true);
    let failure = code.len();
    code.extend_from_slice(&[
        0xb8, 0xe7, 0, 0, 0, 0xbf, 91, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    for operand in failures {
        patch_stats_jump(&mut code, operand, failure);
    }
    let message_address = LOAD_ADDRESS + code.len() as u64;
    code[message_operand..message_operand + 8].copy_from_slice(&message_address.to_le_bytes());
    code.extend_from_slice(message);
    code
}

#[test]
fn direct_and_tool_capture_share_device_with_anonymous_pipe() {
    if !kvm_available("captured output native pipe identity") {
        return;
    }
    let image = static_elf(&capture_identity_program());
    for with_tool in [false, true] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&image, "/bin/capture-identity")
            .unwrap();
        let (status, stdout, stderr) = if with_tool {
            let ((), status, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<CaptureIdentityTool>((), true),
            )
            .unwrap();
            (status, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(status, 0, "with_tool={with_tool}");
        assert_eq!(stdout, b"capture-pipe-ok\n", "with_tool={with_tool}");
        assert!(stderr.is_empty());
    }
}
