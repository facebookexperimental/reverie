/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

use reverie::Subscription;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::codec::encode;

use super::super::rpc::GuestRpcStream;
use super::*;

struct Remote;
impl Default for Remote {
    fn default() -> Self {
        panic!("the coordinator owns this state")
    }
}
#[reverie::global_tool]
impl GlobalTool for Remote {
    type Config = u64;
    type Request = ();
    type Response = ();
    async fn receive_rpc(&self, _: Pid, _: ()) {
        panic!("root initialization must not issue a Tool RPC")
    }
}
#[derive(Default)]
struct Probe {
    events: Mutex<Vec<(&'static str, i32, u64)>>,
}
impl Probe {
    fn record(&self, event: &'static str, state: &(i32, u64)) {
        self.events.lock().unwrap().push((event, state.0, state.1));
    }
}
#[reverie::tool]
impl Tool for Probe {
    type GlobalState = Remote;
    type ThreadState = (i32, u64);
    fn subscriptions(_: &u64) -> Subscription {
        let mut selection = Subscription::from_iter([Sysno::getpid]);
        selection.rdtsc();
        selection
    }
    fn new(_: Pid, config: &u64) -> Self {
        assert_eq!(*config, 71);
        Self::default()
    }
    fn init_thread_state(
        &self,
        tid: Pid,
        parent: Option<(Pid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        (tid.as_raw(), parent.map_or(71, |(_, state)| state.1 + 1))
    }
    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        self.record("thread-start", guest.thread_state());
        Ok(())
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        self.record("post-exec", guest.thread_state());
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(call.number(), Sysno::getpid);
        self.record("syscall", guest.thread_state());
        Ok(guest.thread_state().1 as i64)
    }
    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: Rdtsc,
    ) -> Result<reverie::RdtscResult, Errno> {
        assert_eq!(request, Rdtsc::Tsc);
        self.record("instruction", guest.thread_state());
        Ok(reverie::RdtscResult {
            tsc: guest.thread_state().1,
            aux: None,
        })
    }
}
struct Runtime;
impl HostRuntime for Runtime {
    fn fork_child_rebind(&self) {
        panic!("no physical fork")
    }
    fn emit_stage(&self, _: &[u8]) {}
    fn fork_child_reset(&self, _: &SyscallEvent) {
        panic!("no physical fork")
    }
    fn cpuid_interception_enabled(&self) -> bool {
        false
    }
    fn exit_process_stats(&self, _: Pid) -> io::Result<()> {
        panic!("no exit")
    }
    fn read_clock(&self) -> io::Result<u64> {
        panic!("no clock")
    }
    fn signal_action_supported(&self, _: i64, _: [u64; 6]) -> bool {
        false
    }
    fn reserved_signal_mask(&self) -> u64 {
        0
    }
}
fn host() -> (ToolHost<Probe, Runtime>, UnixStream) {
    host_at(Pid::from_raw(31))
}
fn host_at(pid: Pid) -> (ToolHost<Probe, Runtime>, UnixStream) {
    let (client, mut peer) = UnixStream::pair().unwrap();
    let bytes = encode(&71_u64).unwrap();
    peer.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
    peer.write_all(&bytes).unwrap();
    let tid = raw_pid(libc::SYS_gettid);
    let client =
        BlockingRpcClient::from_connected_stream(GuestRpcStream::from(client), tid).unwrap();
    let rpc = CoordinatorRpc::from_live_client("unused-root-test", client, |_, _| {
        panic!("root test must not reconnect")
    })
    .unwrap();
    let owner = ToolConfiguration::<Probe>::select(rpc.shared_config());
    let tool = owner.new_process(pid);
    let selection = owner.subscriptions().iter_syscalls().collect();
    (
        ToolHost::with_configuration(tool, rpc, pid, owner, selection, Runtime),
        peer,
    )
}

#[test]
fn ordinary_root_handoff_preserves_first_event_and_normal_fields() {
    // The host's modeled root selects this actual calling thread so both real
    // dispatch methods take their root lifecycle branch. No filter, injected
    // syscall, physical guest, private permit or coordinator request is used.
    let root = raw_pid(libc::SYS_gettid);
    for instruction in [false, true] {
        let (mut host, _peer) = host_at(root);
        host.prepare_ordinary_root_state(|config, pid, state| {
            assert_eq!(*config, 71);
            assert_eq!(pid, root);
            assert_eq!(*state, (root.as_raw(), 71));
            state.1 = 97;
            Ok(())
        })
        .unwrap();
        assert!(host.states.lock().is_empty());
        let event_name = if instruction {
            "instruction"
        } else {
            "syscall"
        };
        for _ in 0..2 {
            if instruction {
                let mut context = RegisterContext::default();
                context.instruction_pointer = 0x1234;
                unsafe { host.dispatch_instruction(InstructionEventKind::Rdtsc, &mut context) };
                assert_eq!(context.rax, 97);
                assert_eq!(context.rdx, 0);
            } else {
                let mut event = SyscallEvent {
                    number: libc::SYS_getpid,
                    args: [0; 6],
                    instruction_pointer: 0x1234,
                    result: 0,
                    context: 0,
                    dispatch: SyscallDispatch::InstalledHook,
                    guest_pkru: None,
                };
                unsafe { host.dispatch(&mut event) };
                assert_eq!(event.result, 97);
            }
        }
        let tool = host.tool.lock();
        assert_eq!(
            *tool
                .as_deref()
                .unwrap()
                .as_ref()
                .unwrap()
                .events
                .lock()
                .unwrap(),
            [
                ("thread-start", root.as_raw(), 97),
                ("post-exec", root.as_raw(), 97),
                (event_name, root.as_raw(), 97),
                (event_name, root.as_raw(), 97),
            ]
        );
        assert_eq!(
            host.states.lock().get(&root.as_raw()),
            Some(&(root.as_raw(), 97))
        );
        assert!(host.ordinary_root_state.lock().is_none());
    }
}

#[test]
fn ordinary_root_refusal_cannot_publish_a_default_replacement() {
    let (mut host, _peer) = host();
    let error = host
        .prepare_ordinary_root_state(|_, _, state| {
            state.1 = 97;
            Err(io::Error::from_raw_os_error(libc::ESTALE))
        })
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ESTALE));
    assert!(host.ordinary_root_state.lock().is_none());
    assert!(host.states.lock().is_empty());
    // The standard installer propagates this error before publish_tool/activation.
}

#[test]
fn ordinary_root_preparation_is_one_use_and_does_not_reseed_other_threads() {
    let (mut host, _peer) = host();
    host.prepare_ordinary_root_state(|_, _, state| {
        state.1 = 97;
        Ok(())
    })
    .unwrap();
    let error = host
        .prepare_ordinary_root_state(|_, _, _| panic!("duplicate initializer must not run"))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    let tool = host.tool.lock();
    let tool = tool.as_ref().unwrap();
    assert_eq!(host.new_thread_state(tool, Pid::from_raw(37)), (37, 71));
    assert!(host.ordinary_root_state.lock().is_some());
    let parent = host.new_thread_state(tool, Pid::from_raw(31));
    assert_eq!(parent, (31, 97));
    assert!(host.ordinary_root_state.lock().is_none());
    // The unchanged real fork path derives state from its parent, never from
    // the initializer or a fresh root. These are modeled identities only.
    let child_tool = tool.new_process(Pid::from_raw(41), host.rpc().config());
    let child = child_tool.init_thread_state(Pid::from_raw(43), Some((Pid::from_raw(31), &parent)));
    assert_eq!(child, (43, 98));
}

#[test]
fn existing_installer_without_handoff_keeps_lazy_root_construction() {
    let (host, _peer) = host();
    assert!(host.states.lock().is_empty());
    assert!(host.ordinary_root_state.lock().is_none());
    let tool = host.tool.lock();
    assert_eq!(
        host.new_thread_state(tool.as_ref().unwrap(), Pid::from_raw(31)),
        (31, 71)
    );
}
