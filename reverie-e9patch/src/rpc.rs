//! Coordinator RPC adapter for in-guest e9patch tools.

use core::marker::PhantomData;
use std::io;
use std::path::Path;

use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Pid;
use reverie_preload::rpc::CoordinatorClient;
use reverie_preload::trap::raw_syscall6;

// The async-signal-safe spinlock is shared across the in-guest tool hosts.
pub(crate) use reverie_preload::sync::SpinMutex;

// TODO-HUMAN-REVIEW(PR-269): Review blocking trusted-gate
// RPC semantics for the e9patch generic Tool host.
/// Blocking guest-side RPC handle backed by the shared preload wire protocol.
pub(crate) struct CoordinatorRpc<G: GlobalTool> {
    client: SpinMutex<CoordinatorClient>,
    config: G::Config,
    fd: libc::c_int,
    _global: PhantomData<fn() -> G>,
}

impl<G: GlobalTool> CoordinatorRpc<G> {
    pub(crate) const fn raw_fd(&self) -> libc::c_int {
        self.fd
    }

    pub(crate) fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        let client = CoordinatorClient::connect(path)?;
        let config = client.config::<G::Config>()?;
        let fd = client.raw_fd();
        Ok(Self {
            client: SpinMutex::new(client),
            config,
            fd,
            _global: PhantomData,
        })
    }
}

#[reverie::tool]
impl<G: GlobalTool> GlobalRPC<G> for CoordinatorRpc<G> {
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        // AUTONOMOUS-BOT-IMPLEMENTED
        let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
        if tid <= 0 {
            rpc_fatal(122);
        }
        match self
            .client
            .lock()
            .send_trusted(Pid::from_raw(tid as i32), message)
        {
            Ok(response) => response,
            Err(_) => rpc_fatal(123),
        }
    }

    fn config(&self) -> &G::Config {
        &self.config
    }
}

fn rpc_fatal(status: i32) -> ! {
    // AUTONOMOUS-BOT-IMPLEMENTED
    unsafe {
        let _ = raw_syscall6(libc::SYS_exit_group, [status as u64, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}
