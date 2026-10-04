/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Real CPUID Tool dispatch controls. All guest fixtures are loader-free unless
// a test explicitly installs an executable image for its exec transition.
use reverie::CpuIdResult;

use super::*;

const OUTPUTS: [u32; 4] = [0xf1234567, 0xe2345678, 0xd3456789, 0xc456789a];

#[derive(Debug, Default)]
struct CpuidLog {
    calls: Mutex<Vec<(Pid, u32, u32, u64)>>,
}

#[reverie::global_tool]
impl GlobalTool for CpuidLog {
    type Config = (bool, u8);
    type Request = (u32, u32, u64);
    type Response = ();
    async fn receive_rpc(&self, from: Pid, (eax, ecx, clock): Self::Request) {
        self.calls.lock().unwrap().push((from, eax, ecx, clock));
    }
}

#[derive(Default)]
struct CpuidTool;

#[reverie::tool]
impl Tool for CpuidTool {
    type GlobalState = CpuidLog;
    type ThreadState = u32;

    fn subscriptions(config: &(bool, u8)) -> Subscription {
        let mut subscription = Subscription::none();
        if config.0 {
            subscription.cpuid();
        }
        if config.1 == 3 {
            subscription.rdtsc();
        }
        subscription
    }

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        assert_eq!(guest.has_cpuid_interception(), guest.config().0);
        Ok(())
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        assert_eq!(guest.config().1, 3);
        assert!(guest.has_cpuid_interception());
        let before = guest.read_clock().expect("actual mixed-instruction clock");
        let (kind, result) = match request {
            Rdtsc::Tsc => (
                0,
                RdtscResult {
                    tsc: RDTSC_SENTINEL,
                    aux: None,
                },
            ),
            Rdtsc::Tscp => (
                1,
                RdtscResult {
                    tsc: RDTSCP_SENTINEL,
                    aux: Some(RDTSCP_AUX_SENTINEL),
                },
            ),
        };
        guest.send_rpc((u32::MAX, kind, before)).await;
        assert_eq!(guest.read_clock().unwrap(), before);
        Ok(result)
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        eax: u32,
        ecx: u32,
    ) -> Result<CpuIdResult, Errno> {
        assert!(guest.has_cpuid_interception());
        let registers = guest.regs().await;
        assert_eq!((registers.rax as u32, registers.rcx as u32), (eax, ecx));
        let before = guest.read_clock().expect("actual guest clock");
        assert_eq!(
            guest.inject(reverie::syscalls::Getpid::new()).await?,
            i64::from(guest.pid().as_raw())
        );
        assert_eq!(guest.inject(Fork::new()).await, Err(Errno::ENOSYS));
        guest.send_rpc((eax, ecx, before)).await;
        assert_eq!(
            guest.read_clock().unwrap(),
            before,
            "host RPC/injection must not retire guest branches"
        );
        let ordinal = *guest.thread_state();
        *guest.thread_state_mut() = ordinal + 1;
        let values = if guest.config().1 == 2 {
            [RDTSC_SENTINEL as u32, 0, 0, (RDTSC_SENTINEL >> 32) as u32]
        } else {
            OUTPUTS.map(|value| value + if guest.config().1 == 1 { ordinal } else { 0 })
        };
        Ok(CpuIdResult {
            eax: values[0],
            ebx: values[1],
            ecx: values[2],
            edx: values[3],
        })
    }
}

fn append_cpuid(code: &mut Vec<u8>, prefix: &[u8], ordinal: u32, failures: &mut Vec<usize>) {
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&0x8877665500000007_u64.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xb9]);
    code.extend_from_slice(&0x1234567800000002_u64.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xbb]);
    code.extend_from_slice(&u64::MAX.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xba]);
    code.extend_from_slice(&u64::MAX.to_le_bytes());
    code.extend_from_slice(&[0x49, 0xb8]);
    code.extend_from_slice(&0x123456789abcdef0_u64.to_le_bytes());
    code.extend_from_slice(&[0x49, 0x89, 0xe4]); // mov r12,rsp
    code.extend_from_slice(&[0x68, 0xd7, 0x02, 0, 0, 0x9d]); // push flags; popfq
    code.extend_from_slice(prefix);
    code.extend_from_slice(&[0x0f, 0xa2]);
    code.extend_from_slice(&[0x9c, 0x41, 0x5b]); // pushfq; pop r11
    code.extend_from_slice(&[0x49, 0x81, 0xfb, 0xd7, 0x02, 0, 0]);
    append_jne_failure(code, failures);
    for (register, value) in [0_u8, 3, 1, 2].into_iter().zip(OUTPUTS) {
        code.extend_from_slice(&[0x49, 0xba]);
        code.extend_from_slice(&u64::from(value + ordinal).to_le_bytes());
        code.extend_from_slice(&[0x4c, 0x39, 0xd0 | register]);
        append_jne_failure(code, failures);
    }
    code.extend_from_slice(&[0x49, 0xba]);
    code.extend_from_slice(&0x123456789abcdef0_u64.to_le_bytes());
    code.extend_from_slice(&[0x4d, 0x39, 0xd0]);
    append_jne_failure(code, failures); // cmp r8,r10
    code.extend_from_slice(&[0x4c, 0x39, 0xe4]);
    append_jne_failure(code, failures); // cmp rsp,r12
}

fn assertion_program(prefix: &[u8], count: u32, evolving: bool) -> Vec<u8> {
    let mut code = Vec::new();
    let mut failures = Vec::new();
    for ordinal in 0..count {
        append_cpuid(
            &mut code,
            prefix,
            if evolving { ordinal } else { 0 },
            &mut failures,
        );
    }
    append_stats_exit(&mut code, true);
    let failure = code.len();
    code.extend_from_slice(&[
        0xb8, 0xe7, 0, 0, 0, 0xbf, 19, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    for operand in failures {
        patch_stats_jump(&mut code, operand, failure);
    }
    code
}

fn run_cpuid(code: &[u8], config: (bool, u8), ownership: ThreadOwnership) -> (CpuidLog, i32) {
    let mut backend = KvmBackend::new(MEMORY_SIZE).expect("actual KVM is mandatory");
    backend.set_thread_ownership(ownership);
    backend
        .install_static_elf(&static_elf(code), "/cpuid-dispatch")
        .unwrap();
    let (log, status, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<CpuidTool>(config, true))
            .unwrap();
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    (log, status)
}

#[test]
fn cpuid_tool_returns_exact_full_registers_flags_stack_and_one_rpc_per_instruction() {
    for prefix in [
        vec![],
        vec![0x66],
        vec![0x67],
        vec![0xf2],
        vec![0xf3],
        vec![0x64],
        vec![0x4f],
        vec![0x66; 13],
    ] {
        let (log, status) = run_cpuid(
            &assertion_program(&prefix, 1, false),
            (true, 0),
            ThreadOwnership::Tool,
        );
        assert_eq!(status, 0, "prefix={prefix:x?}");
        let calls = log.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!((calls[0].0.as_raw(), calls[0].1, calls[0].2), (1, 7, 2));
    }
    let (log, status) = run_cpuid(
        &assertion_program(&[], 3, true),
        (true, 1),
        ThreadOwnership::Tool,
    );
    assert_eq!(status, 0);
    let calls = log.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert!(
        calls
            .iter()
            .all(|call| (call.0.as_raw(), call.1, call.2) == (1, 7, 2))
    );
    assert!(
        calls.windows(2).all(|pair| pair[1].3 > pair[0].3),
        "guest comparison branches must advance the real guest clock"
    );
}

#[test]
fn cpuid_subscription_keeps_unrelated_locked_overlength_and_debug_faults_exact() {
    let mut overlong = vec![0x66; 14];
    overlong.extend_from_slice(&[0x0f, 0xa2]);
    for (code, vector, rip, calls) in [
        (vec![0xf0, 0x0f, 0xa2], 6, LOAD_ADDRESS, 0),
        (overlong, 13, LOAD_ADDRESS, 0),
        (vec![0xfa], 13, LOAD_ADDRESS, 0),
        (vec![0x0f, 0x0b], 6, LOAD_ADDRESS, 0),
        (
            vec![
                0x9c, 0x48, 0x81, 0x0c, 0x24, 0x00, 0x01, 0, 0, 0x9d, 0x0f, 0xa2,
            ],
            1,
            LOAD_ADDRESS + 12,
            1,
        ),
    ] {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&static_elf(&code), "/cpuid-fault")
            .unwrap();
        let completion = futures::executor::block_on(
            backend.run_static_elf_with_tool_completion::<CpuidTool>((true, 0), true),
        )
        .unwrap();
        let error = completion.result.unwrap_err();
        let Error::GuestException {
            vector: actual_vector,
            instruction_pointer: actual_rip,
            ..
        } = unwrap_shared_guest_exception(error)
        else {
            panic!("exact guest exception required");
        };
        assert_eq!((actual_vector, actual_rip), (vector, rip));
        assert_eq!(completion.global_state.calls.lock().unwrap().len(), calls);
    }
}

fn cpuid_clone_program() -> Vec<u8> {
    fn append_root_read(code: &mut Vec<u8>, failures: &mut Vec<usize>) {
        code.extend_from_slice(&[0x0f, 0xa2]); // cpuid
        code.push(0x3d); // cmp eax, expected low word
        code.extend_from_slice(&(RDTSC_SENTINEL as u32).to_le_bytes());
        append_jne_failure(code, failures);
        code.extend_from_slice(&[0x81, 0xfa]); // cmp edx, expected high word
        code.extend_from_slice(&((RDTSC_SENTINEL >> 32) as u32).to_le_bytes());
        append_jne_failure(code, failures);
    }

    const CHILD_TID: u64 = LOAD_ADDRESS + 0x1800;
    const CHILD_RESULT: u64 = LOAD_ADDRESS + 0x1808;
    const CHILD_DONE: u64 = LOAD_ADDRESS + 0x1810;
    const CHILD_STACK: u64 = LOAD_ADDRESS + 0x1900;
    const CHILD_STACK_SIZE: u64 = 0x600;
    let flags = libc::CLONE_VM as u64
        | libc::CLONE_FS as u64
        | libc::CLONE_FILES as u64
        | libc::CLONE_SIGHAND as u64
        | libc::CLONE_THREAD as u64
        | libc::CLONE_SYSVSEM as u64
        | libc::CLONE_CHILD_SETTID as u64
        | libc::CLONE_CHILD_CLEARTID as u64;
    let mut code = Vec::new();
    let mut failures = Vec::new();
    append_root_read(&mut code, &mut failures);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    code.extend_from_slice(&[
        0xc7, 0x01, 0xff, 0xff, 0xff, 0x7f, // mov [rcx], nonzero sentinel
        0xb8, 0xb3, 0x01, 0x00, 0x00, // mov eax, SYS_clone3
        0x48, 0xbf, // movabs rdi, clone_args
    ]);
    let clone_args_operand = code.len();
    code.extend_from_slice(&0_u64.to_le_bytes());
    code.extend_from_slice(&[
        0xbe, 0x58, 0x00, 0x00, 0x00, // mov esi, sizeof(clone_args)
        0x0f, 0x05, // syscall
        0x85, 0xc0, // test eax, eax
        0x0f, 0x84, 0, 0, 0, 0, // jz child
    ]);
    let child_jump = code.len() - 4;
    code.extend_from_slice(&[0x0f, 0x88]); // js failure: clone must succeed
    failures.push(code.len());
    code.extend_from_slice(&0_i32.to_le_bytes());
    code.extend_from_slice(&[0x41, 0x89, 0xc5]); // mov r13d, returned child tid
    code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, child_tid
    code.extend_from_slice(&CHILD_TID.to_le_bytes());
    let wait = code.len();
    code.extend_from_slice(&[
        0x8b, 0x17, // mov edx, [rdi]
        0x85, 0xd2, // test edx, edx
        0x0f, 0x84, 0, 0, 0, 0, // jz joined
    ]);
    let joined_jump = code.len() - 4;
    code.extend_from_slice(&[
        0x31, 0xf6, // xor esi, esi: FUTEX_WAIT, current nonzero value in edx
        0x45, 0x31, 0xd2, // xor r10d, r10d: no timeout
        0xb8, 0xca, 0x00, 0x00, 0x00, // mov eax, SYS_futex
        0x0f, 0x05, // syscall
    ]);
    // A racing clear-TID may win before FUTEX_WAIT. Only Linux's normal
    // successful wake, changed-value refusal or signal interruption can retry.
    for result in [0_i32, -libc::EAGAIN, -libc::EINTR] {
        code.push(0x3d); // cmp eax, result
        code.extend_from_slice(&result.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // je wait
        let operand = code.len() - 4;
        patch_stats_jump(&mut code, operand, wait);
    }
    code.push(0xe9); // jmp failure for any other futex result
    failures.push(code.len());
    code.extend_from_slice(&0_i32.to_le_bytes());
    let joined = code.len();
    patch_stats_jump(&mut code, joined_jump, joined);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_result
    code.extend_from_slice(&CHILD_RESULT.to_le_bytes());
    code.extend_from_slice(&[0x44, 0x39, 0x29]); // cmp [rcx], r13d
    append_jne_failure(&mut code, &mut failures);
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_done
    code.extend_from_slice(&CHILD_DONE.to_le_bytes());
    code.extend_from_slice(&[0x81, 0x39, 0x34, 0x12, 0x00, 0x00]); // cmp [rcx], 0x1234
    append_jne_failure(&mut code, &mut failures);
    append_root_read(&mut code, &mut failures);
    append_stats_exit(&mut code, true);

    let child = code.len();
    patch_stats_jump(&mut code, child_jump, child);
    code.extend_from_slice(&[
        0x0f, 0xa2, // actual Host-worker CPUID: must retire without a Tool callback
        0xb8, 0xba, 0x00, 0x00, 0x00, // mov eax, SYS_gettid
        0x0f, 0x05, // syscall
        0x48, 0xb9, // movabs rcx, child_result
    ]);
    code.extend_from_slice(&CHILD_RESULT.to_le_bytes());
    code.extend_from_slice(&[0x89, 0x01]); // mov [rcx], eax
    code.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, child_done
    code.extend_from_slice(&CHILD_DONE.to_le_bytes());
    code.extend_from_slice(&[0xc7, 0x01, 0x34, 0x12, 0x00, 0x00]); // mov [rcx], 0x1234
    append_stats_exit(&mut code, false); // clear-TID and wake parent on real exit

    let failure = code.len();
    code.extend_from_slice(&[
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
    ]);
    for operand in failures {
        patch_stats_jump(&mut code, operand, failure);
    }
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
    assert!(
        code.len() < 0x1000,
        "code must not overlap the shared data page"
    );
    code
}

#[test]
fn cpuid_thread_ownership_keeps_host_worker_native_and_tool_worker_subscribed() {
    for (ownership, expected) in [
        (ThreadOwnership::Host, vec![1, 1]),
        (ThreadOwnership::Tool, vec![1, 2, 1]),
    ] {
        let (log, status) = run_cpuid(&cpuid_clone_program(), (true, 2), ownership);
        assert_eq!(status, 0);
        assert_eq!(
            log.calls
                .lock()
                .unwrap()
                .iter()
                .map(|row| row.0.as_raw())
                .collect::<Vec<_>>(),
            expected
        );
    }
}

fn table_program(leaf: u32, subleaf: u32, values: [u32; 4]) -> Vec<u8> {
    let mut code = vec![0xb8];
    code.extend_from_slice(&leaf.to_le_bytes());
    code.push(0xb9);
    code.extend_from_slice(&subleaf.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0xa2]);
    let mut failures = Vec::new();
    for (register, value) in [0_u8, 3, 1, 2].into_iter().zip(values) {
        code.extend_from_slice(&[0x49, 0xba]);
        code.extend_from_slice(&u64::from(value).to_le_bytes());
        code.extend_from_slice(&[0x4c, 0x39, 0xd0 | register]);
        append_jne_failure(&mut code, &mut failures);
    }
    append_stats_exit(&mut code, true);
    let failure = code.len();
    code.extend_from_slice(&[
        0xb8, 0xe7, 0, 0, 0, 0xbf, 20, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    for operand in failures {
        patch_stats_jump(&mut code, operand, failure);
    }
    code
}

#[test]
fn unsubscribed_cpuid_keeps_the_installed_table_and_indexed_xstate_policy() {
    for (leaf, subleaf, expected) in [
        (0x80000001, 0, [0x663, 0, 1, 0x20100800]),
        (0xd, 1, [0; 4]),
        (0xd, 17, [0; 4]),
        (0xd, 19, [0; 4]),
    ] {
        let (log, status) = run_cpuid(
            &table_program(leaf, subleaf, expected),
            (false, 0),
            ThreadOwnership::Tool,
        );
        assert_eq!(status, 0, "leaf={leaf:#x}, subleaf={subleaf}");
        assert!(log.calls.lock().unwrap().is_empty());
    }
}

#[test]
fn cpuid_dispatch_survives_real_fork_and_same_pid_exec() {
    let directory = TestDirectory::new();
    let executable = directory.0.join("cpuid-exec-target");
    let child_image = static_elf(&assertion_program(&[], 1, false));
    std::fs::write(&executable, &child_image).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut code = Vec::new();
    let mut failures = Vec::new();
    append_cpuid(&mut code, &[], 0, &mut failures);
    code.extend_from_slice(&[
        0xb8, 57, 0, 0, 0, 0x0f, 0x05, 0x85, 0xc0, 0x0f, 0x84, 0, 0, 0, 0,
    ]);
    let child_jump = code.len() - 4;
    code.extend_from_slice(&[0x0f, 0x88]);
    failures.push(code.len());
    code.extend_from_slice(&0_i32.to_le_bytes());
    code.extend_from_slice(&[
        0x49, 0x89, 0xc5, // mov r13,rax: exact child identity
        0x48, 0x89, 0xc7, // mov rdi,rax: wait for that child
        0x48, 0x83, 0xec, 0x10, // sub rsp,16: real writable guest stack
        0x48, 0x89, 0xe6, // mov rsi,rsp: wait status
        0xc7, 0x06, 0xff, 0xff, 0xff, 0xff, // status sentinel, overwritten by wait4
    ]);
    code.extend_from_slice(&[
        0x31, 0xd2, 0x45, 0x31, 0xd2, 0xb8, 61, 0, 0, 0, 0x0f, 0x05, 0x4c, 0x39, 0xe8,
    ]);
    append_jne_failure(&mut code, &mut failures);
    code.extend_from_slice(&[0x83, 0x3e, 0]);
    append_jne_failure(&mut code, &mut failures);
    append_stats_exit(&mut code, true);
    let child = code.len();
    patch_stats_jump(&mut code, child_jump, child);
    append_cpuid(&mut code, &[], 0, &mut failures);
    code.extend_from_slice(&[0x48, 0xbf]);
    let path_operand = code.len();
    code.extend_from_slice(&0_u64.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xbe]);
    let argv_operand = code.len();
    code.extend_from_slice(&0_u64.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xd2, 0xb8, 59, 0, 0, 0, 0x0f, 0x05]); // a returned exec is failure
    let failure = code.len();
    code.extend_from_slice(&[
        0xb8, 0xe7, 0, 0, 0, 0xbf, 21, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    for operand in failures {
        patch_stats_jump(&mut code, operand, failure);
    }
    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let path = LOAD_ADDRESS + code.len() as u64;
    code.extend_from_slice(executable.to_str().unwrap().as_bytes());
    code.push(0);
    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let argv = LOAD_ADDRESS + code.len() as u64;
    code.extend_from_slice(&path.to_le_bytes());
    code.extend_from_slice(&0_u64.to_le_bytes());
    for (operand, value) in [(path_operand, path), (argv_operand, argv)] {
        code[operand..operand + 8].copy_from_slice(&value.to_le_bytes());
    }
    let (log, status) = run_cpuid(&code, (true, 0), ThreadOwnership::Tool);
    assert_eq!(status, 0);
    assert_eq!(
        log.calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| (call.0.as_raw(), call.1, call.2))
            .collect::<Vec<_>>(),
        vec![(1, 7, 2), (2, 7, 2), (2, 7, 2)]
    );
}

#[test]
fn cpuid_and_both_timestamp_forms_share_one_real_dispatcher_without_cross_charges() {
    let mut code = Vec::new();
    let mut failures = Vec::new();
    append_cpuid(&mut code, &[], 0, &mut failures);
    // Retain the existing complete RDTSC/RDTSCP guest result and AUX checks.
    // Its relative jumps remain local when placed after the CPUID assertion.
    code.extend_from_slice(&timestamp_assertion_program());
    let failure = code.len();
    code.extend_from_slice(&[
        0xb8, 0xe7, 0, 0, 0, 0xbf, 22, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    for operand in failures {
        patch_stats_jump(&mut code, operand, failure);
    }
    let (log, status) = run_cpuid(&code, (true, 3), ThreadOwnership::Tool);
    assert_eq!(status, 0);
    let calls = log.calls.lock().unwrap();
    assert_eq!(
        calls
            .iter()
            .map(|call| (call.0.as_raw(), call.1, call.2))
            .collect::<Vec<_>>(),
        vec![(1, 7, 2), (1, u32::MAX, 0), (1, u32::MAX, 1)]
    );
    assert!(calls.windows(2).all(|pair| pair[1].3 > pair[0].3));
}
