/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! External consumers exercise only the public guest and syscall driver APIs.

use std::cell::Cell;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use reverie::Error;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::InjectionPurpose;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_dbt::DbtGuest;
use reverie_dbt::DbtSyscallOutcome;
use reverie_dbt::run_tool_syscall_with_guest;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::RequestEnvelope;
use reverie_rpc_transport::codec::decode_exact;
use reverie_rpc_transport::codec::encode;
use reverie_rpc_transport::read_config_frame;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct Config {
    request: u8,
    response: u64,
}

struct RemoteGlobal;

impl Default for RemoteGlobal {
    fn default() -> Self {
        panic!("the endpoint owns the global state")
    }
}

#[reverie::global_tool]
impl GlobalTool for RemoteGlobal {
    type Config = Config;
    type Request = Vec<u8>;
    type Response = u64;

    async fn receive_rpc(&self, _from: Pid, _request: Vec<u8>) -> u64 {
        panic!("no local-global fallback is permitted")
    }
}

fn write_frame(stream: &mut UnixStream, value: &impl Serialize) {
    let bytes = encode(value).unwrap();
    stream
        .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
}

fn with_endpoint(exercise: impl FnOnce(&BlockingRpcClient<RemoteGlobal>)) {
    let config = Config {
        request: 71,
        response: 83,
    };
    let (client, mut server) = UnixStream::pair().unwrap();
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    let expected = config.clone();
    let server = std::thread::spawn(move || {
        write_frame(&mut server, &config);
        let request: RequestEnvelope<Vec<u8>> =
            decode_exact(&read_config_frame(&mut server).unwrap()).unwrap();
        assert_eq!(request.from, Pid::from_raw(29));
        assert_eq!(request.request, [71]);
        write_frame(&mut server, &83_u64);
        assert_eq!(server.read(&mut [0; 1]).unwrap(), 0, "duplicate request");
    });
    let rpc = BlockingRpcClient::<RemoteGlobal>::from_connected_stream(client, Pid::from_raw(29))
        .unwrap();
    assert_eq!(rpc.config(), &expected);
    exercise(&rpc);
    drop(rpc);
    server.join().unwrap();
}

struct Invocation {
    calls: Cell<usize>,
    registers: Cell<usize>,
}

unsafe extern "C" fn invoke(context: usize, number: i64, args: *const u64, purpose: u32) -> i64 {
    // SAFETY: each guest borrows this live Invocation for its entire callback.
    let state = unsafe { &*(context as *const Invocation) };
    assert_eq!(number, libc::SYS_write);
    assert_eq!(
        unsafe { args.cast::<[u64; 6]>().read() },
        [1, 0x1000, 7, 0, 0, 0]
    );
    assert_eq!(purpose, InjectionPurpose::Application as u32);
    state.calls.set(state.calls.get() + 1);
    5
}

unsafe extern "C" fn read_registers(context: usize, out: *mut libc::user_regs_struct) -> i32 {
    let state = unsafe { &*(context as *const Invocation) };
    state.registers.set(state.registers.get() + 1);
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    regs.rip = 0x1234;
    regs.rbp = FP as u64;
    unsafe { out.write(regs) };
    1
}

unsafe extern "C" fn write_registers(_: usize, _: *const libc::user_regs_struct) -> i32 {
    panic!("the syscall driver must not rewrite registers")
}

fn guest<'a, T: Tool<GlobalState = RemoteGlobal, ThreadState = u64>>(
    invocation: &'a Invocation,
    state: &'a mut u64,
    rpc: &'a dyn GlobalRPC<RemoteGlobal>,
) -> DbtGuest<'a, T> {
    let guest = DbtGuest::new_with_rpc(
        invocation as *const Invocation as usize,
        Pid::from_raw(29),
        Pid::from_raw(23),
        Some(Pid::from_raw(17)),
        37,
        state,
        rpc,
        invoke,
        read_registers,
        write_registers,
    );
    assert!(std::ptr::eq(guest.config(), rpc.config()));
    guest
}

fn original_call() -> Syscall {
    Syscall::from_raw(Sysno::write, SyscallArgs::new(1, 0x1000, 7, 0, 0, 0))
}

#[derive(Default)]
struct ReturningTool;

#[reverie::tool]
impl Tool for ReturningTool {
    type GlobalState = RemoteGlobal;
    type ThreadState = u64;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(guest.tid(), Pid::from_raw(29));
        assert_eq!(guest.pid(), Pid::from_raw(23));
        assert_eq!(guest.ppid(), Some(Pid::from_raw(17)));
        assert_eq!(guest.read_clock()?, 37);
        assert_eq!(guest.config().request, 71);
        let response = guest.send_rpc(vec![guest.config().request]).await;
        assert_eq!(response, guest.config().response);
        *guest.thread_state_mut() += response;
        let result = guest.inject(syscall).await?;
        assert_eq!(guest.injected_syscalls(), Some(1));
        Ok(result)
    }
}

#[test]
fn borrowed_endpoint_returns_once_without_selecting_an_ambient_coordinator() {
    const CHILD: &str = "REVERIE_DBT_PUBLIC_DRIVER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let directory = tempfile::tempdir().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "borrowed_endpoint_returns_once_without_selecting_an_ambient_coordinator",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .env(
                reverie_dbt::sync_rpc::RPC_SOCKET_ENV,
                directory.path().join("absent"),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                panic!(
                    "public driver timed out: {:?}",
                    child.wait_with_output().unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("test result: ok. 1 passed;")
        );
        return;
    }
    assert!(reverie_dbt::sync_rpc::is_active());
    with_endpoint(|rpc| {
        let invocation = Invocation {
            calls: Cell::new(0),
            registers: Cell::new(0),
        };
        let mut state = 11;
        let result = run_tool_syscall_with_guest(
            &ReturningTool,
            guest(&invocation, &mut state, rpc),
            original_call(),
        )
        .unwrap();
        assert!(matches!(result, DbtSyscallOutcome::Suppress(5)));
        assert_eq!(state, 94);
        assert_eq!(invocation.calls.get(), 1);
    });
}

#[derive(Default)]
struct TailTool;

#[reverie::tool]
impl Tool for TailTool {
    type GlobalState = RemoteGlobal;
    type ThreadState = u64;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        _: Syscall,
    ) -> Result<i64, Error> {
        if *guest.thread_state() == 11 {
            let response = guest.send_rpc(vec![guest.config().request]).await;
            *guest.thread_state_mut() += response;
            guest
                .tail_inject(Syscall::from_raw(
                    Sysno::write,
                    SyscallArgs::new(2, 0x2000, 9, 0, 0, 0),
                ))
                .await
        } else {
            assert_eq!(*guest.thread_state(), 94);
            Ok(19)
        }
    }
}

#[test]
fn tail_injection_preserves_the_rewrite_without_executing_or_reusing_it() {
    with_endpoint(|rpc| {
        let invocation = Invocation {
            calls: Cell::new(0),
            registers: Cell::new(0),
        };
        let mut state = 11;
        let result = run_tool_syscall_with_guest(
            &TailTool,
            guest(&invocation, &mut state, rpc),
            original_call(),
        )
        .unwrap();
        let DbtSyscallOutcome::ExecuteOriginal(call) = result else {
            panic!("missing tail action")
        };
        let (number, args) = call.into_parts();
        assert_eq!(number, Sysno::write);
        assert_eq!(
            [
                args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5
            ],
            [2, 0x2000, 9, 0, 0, 0]
        );
        assert_eq!(state, 94);
        assert_eq!(invocation.calls.get(), 0);
        let result = run_tool_syscall_with_guest(
            &TailTool,
            guest(&invocation, &mut state, rpc),
            original_call(),
        )
        .unwrap();
        assert!(matches!(result, DbtSyscallOutcome::Suppress(19)));
        assert_eq!(invocation.calls.get(), 0);
    });
}

// These noncanonical x86-64 addresses cannot be mapped by a userspace process,
// including on hosts with five-level paging. Only the supplied reader answers.
const FP: usize = 0x8000_0000_0000_0000;
const SAVED_FP: usize = FP + 0x100;
static READS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

unsafe extern "C" fn read_memory(address: usize, out: *mut u8, size: usize) -> i32 {
    assert_eq!(size, 8);
    READS.lock().unwrap().push(address);
    let value = if address == FP {
        SAVED_FP as u64
    } else if address == FP + 8 {
        0x5678
    } else {
        assert_eq!(address, SAVED_FP);
        return 0;
    };
    unsafe { out.cast::<u64>().write(value) };
    1
}

struct NoRpc(Config);

#[reverie::tool]
impl GlobalRPC<RemoteGlobal> for NoRpc {
    async fn send_rpc(&self, _: Vec<u8>) -> u64 {
        panic!("reader test must not issue RPC")
    }
    fn config(&self) -> &Config {
        &self.0
    }
}

#[derive(Default)]
struct ReaderTool;

#[reverie::tool]
impl Tool for ReaderTool {
    type GlobalState = RemoteGlobal;
    type ThreadState = u64;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        _: Syscall,
    ) -> Result<i64, Error> {
        let backtrace = guest.backtrace().unwrap();
        assert_eq!(backtrace.thread_id(), Pid::from_raw(29));
        assert_eq!(
            backtrace
                .iter()
                .map(|frame| (frame.ip, frame.is_signal))
                .collect::<Vec<_>>(),
            [(0x1234, false), (0x5678, false)]
        );
        Ok(23)
    }
}

#[test]
fn public_driver_preserves_the_optional_reader_and_stops_at_its_refusal() {
    // Independently establish that the ordinary read fallback cannot answer.
    for address in [FP, FP + 8, SAVED_FP] {
        let mut word = 0_u64;
        let local = libc::iovec {
            iov_base: (&mut word as *mut u64).cast(),
            iov_len: 8,
        };
        let remote = libc::iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: 8,
        };
        assert_eq!(
            unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EFAULT)
        );
    }
    READS.lock().unwrap().clear();
    let invocation = Invocation {
        calls: Cell::new(0),
        registers: Cell::new(0),
    };
    let rpc = NoRpc(Config::default());
    let mut state = 11;
    let guest = guest::<ReaderTool>(&invocation, &mut state, &rpc).with_memory_reader(read_memory);
    assert!(matches!(
        run_tool_syscall_with_guest(&ReaderTool, guest, original_call()).unwrap(),
        DbtSyscallOutcome::Suppress(23)
    ));
    assert_eq!(*READS.lock().unwrap(), [FP, FP + 8, SAVED_FP]);
    assert_eq!(invocation.registers.get(), 1);
    assert_eq!(invocation.calls.get(), 0);
    assert_eq!(state, 11);
}
