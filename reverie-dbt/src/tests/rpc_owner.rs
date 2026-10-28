/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::RequestEnvelope;
use reverie_rpc_transport::codec::decode_exact;
use reverie_rpc_transport::codec::encode;
use reverie_rpc_transport::read_config_frame;

use super::*;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct Config {
    request: u8,
    response: u64,
}

struct RemoteGlobal;

impl Default for RemoteGlobal {
    fn default() -> Self {
        panic!("a borrowed RPC endpoint must not construct a local GlobalTool")
    }
}

#[reverie::global_tool]
impl GlobalTool for RemoteGlobal {
    type Config = Config;
    type Request = Vec<u8>;
    type Response = u64;

    async fn receive_rpc(&self, _from: Pid, _message: Vec<u8>) -> u64 {
        panic!("a borrowed RPC endpoint must not fall back to a local GlobalTool")
    }
}

#[derive(Default)]
struct ConfiguredProbe;

#[reverie::tool]
impl Tool for ConfiguredProbe {
    type GlobalState = RemoteGlobal;
    type ThreadState = u64;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(guest.config().request, 71);
        let response = guest.send_rpc(vec![guest.config().request]).await;
        assert_eq!(response, guest.config().response);
        *guest.thread_state_mut() += response;
        Ok(guest.inject(syscall).await?)
    }
}

fn write_frame(stream: &mut UnixStream, value: &impl Serialize) {
    let bytes = encode(value).unwrap();
    stream
        .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
}

#[test]
fn borrowed_rpc_retains_config_and_returns_the_native_result_once() {
    let config = Config {
        request: 71,
        response: 83,
    };
    let tid = Pid::from_raw(29);
    let pid = Pid::from_raw(23);
    let (client, mut server) = UnixStream::pair().unwrap();
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    let expected_config = config.clone();
    let server = std::thread::spawn(move || {
        write_frame(&mut server, &config);
        let request: RequestEnvelope<Vec<u8>> =
            decode_exact(&read_config_frame(&mut server).unwrap()).unwrap();
        assert_eq!(request.from, tid);
        assert_eq!(request.request, [config.request]);
        write_frame(&mut server, &config.response);
        // Dropping the only client must close the connection after exactly
        // one request, not send a fallback or duplicate request.
        assert_eq!(server.read(&mut [0u8; 1]).unwrap(), 0);
    });
    let rpc = BlockingRpcClient::<RemoteGlobal>::from_connected_stream(client, tid).unwrap();
    assert_eq!(rpc.config(), &expected_config);
    let expected = ExpectedInvocation {
        sysnum: libc::SYS_write,
        args: [1, 0x1000, 7, 0, 0, 0],
        result: 5,
        calls: std::cell::Cell::new(0),
    };
    let mut state = 11;
    {
        let mut guest = DbtGuest::<ConfiguredProbe>::new_with_rpc(
            (&expected as *const ExpectedInvocation) as usize,
            tid,
            pid,
            None,
            0,
            &mut state,
            &rpc,
            invoke_expected,
            read_regs,
            write_regs_noop,
        );
        assert_eq!(guest.tid(), tid);
        assert_eq!(guest.pid(), pid);
        assert!(std::ptr::eq(guest.config(), rpc.config()));
        // BlockingRpcClient does not opt into the optional synchronous hook.
        // The original allocation must be returned without any wire traffic.
        let request = vec![17, 19];
        let allocation = request.as_ptr();
        let returned = guest.try_send_rpc_sync(request).unwrap_err();
        assert_eq!(returned, [17, 19]);
        assert_eq!(returned.as_ptr(), allocation);
        let syscall = Syscall::from_raw(Sysno::write, SyscallArgs::new(1, 0x1000, 7, 0, 0, 0));
        let tail = Arc::clone(&guest.tail_inject_result);
        assert_eq!(
            run_ready(
                ConfiguredProbe.handle_syscall_event(&mut guest, syscall),
                &tail,
            )
            .unwrap()
            .unwrap(),
            expected.result,
        );
        assert_eq!(guest.injected_syscalls(), Some(1));
    }
    assert_eq!(state, 94);
    assert_eq!(expected.calls.get(), 1);
    drop(rpc);
    server.join().unwrap();
}

struct SynchronousRpc {
    config: Config,
    requests: Mutex<Vec<Vec<u8>>>,
}

#[reverie::tool]
impl GlobalRPC<RemoteGlobal> for SynchronousRpc {
    async fn send_rpc(&self, _message: Vec<u8>) -> u64 {
        panic!("the synchronous hook must not dispatch the async hook")
    }

    fn try_send_rpc_sync(&self, message: Vec<u8>) -> Result<u64, Vec<u8>> {
        self.requests.lock().unwrap().push(message);
        Ok(self.config.response)
    }

    fn config(&self) -> &Config {
        &self.config
    }
}

#[test]
fn borrowed_rpc_forwards_the_optional_synchronous_hook_once() {
    let rpc = SynchronousRpc {
        config: Config {
            request: 23,
            response: 97,
        },
        requests: Mutex::new(Vec::new()),
    };
    let mut state = 0;
    let guest = DbtGuest::<ConfiguredProbe>::new_with_rpc(
        0,
        Pid::from_raw(31),
        Pid::from_raw(37),
        None,
        0,
        &mut state,
        &rpc,
        invoke,
        read_regs,
        write_regs_noop,
    );
    assert_eq!(guest.tid(), Pid::from_raw(31));
    assert_eq!(guest.pid(), Pid::from_raw(37));
    assert!(std::ptr::eq(guest.config(), &rpc.config));
    assert_eq!(guest.try_send_rpc_sync(vec![23]), Ok(97));
    assert_eq!(*rpc.requests.lock().unwrap(), [vec![23]]);
}

#[derive(Default)]
struct LocalGlobal {
    requests: Mutex<Vec<(Pid, Vec<u8>)>>,
}

#[reverie::global_tool]
impl GlobalTool for LocalGlobal {
    type Config = u64;
    type Request = Vec<u8>;
    type Response = u64;

    async fn receive_rpc(&self, from: Pid, message: Vec<u8>) -> u64 {
        self.requests.lock().unwrap().push((from, message));
        83
    }
}

#[derive(Default)]
struct LocalProbe;

#[reverie::tool]
impl Tool for LocalProbe {
    type GlobalState = LocalGlobal;
    type ThreadState = u64;
}

#[test]
fn legacy_constructor_preserves_local_routing_and_sync_refusal() {
    const CHILD: &str = "REVERIE_DBT_RPC_OWNER_LOCAL_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let (_, module) = module_path!().split_once("::").unwrap();
        let name = format!("{module}::legacy_constructor_preserves_local_routing_and_sync_refusal");
        // Select the existing uncoordinated route in an isolated process,
        // without changing the parallel parent libtest's environment.
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--test-threads=1"])
            .env(CHILD, "1")
            .env_remove(sync_rpc::RPC_SOCKET_ENV)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!("legacy RPC control timed out: {output:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("test result: ok. 1 passed;"),
            "the exact child test did not run"
        );
        return;
    }
    assert!(!sync_rpc::is_active());
    let global = LocalGlobal::default();
    let config = 71;
    let tid = Pid::from_raw(43);
    let pid = Pid::from_raw(41);
    let expected = ExpectedInvocation {
        sysnum: libc::SYS_write,
        args: [1, 0x1000, 7, 0, 0, 0],
        result: 3,
        calls: std::cell::Cell::new(0),
    };
    let mut state = 11;
    let mut guest = DbtGuest::<LocalProbe>::new(
        (&expected as *const ExpectedInvocation) as usize,
        tid,
        pid,
        None,
        0,
        &mut state,
        &global,
        &config,
        invoke_expected,
        read_regs,
        write_regs_noop,
    );
    assert_eq!(guest.tid(), tid);
    assert_eq!(guest.pid(), pid);
    assert!(std::ptr::eq(guest.config(), &config));
    let request = vec![17, 19];
    let allocation = request.as_ptr();
    let refused = guest.try_send_rpc_sync(request).unwrap_err();
    assert_eq!(refused, [17, 19]);
    assert_eq!(refused.as_ptr(), allocation);
    assert!(global.requests.lock().unwrap().is_empty());
    let tail = Arc::clone(&guest.tail_inject_result);
    assert_eq!(run_ready(guest.send_rpc(vec![71]), &tail), Some(83));
    assert_eq!(*global.requests.lock().unwrap(), [(tid, vec![71])]);
    let syscall = Syscall::from_raw(Sysno::write, SyscallArgs::new(1, 0x1000, 7, 0, 0, 0));
    assert_eq!(
        run_ready(guest.inject(syscall), &tail).unwrap().unwrap(),
        expected.result
    );
    assert_eq!(expected.calls.get(), 1);
    assert_eq!(*guest.thread_state(), 11);
}
