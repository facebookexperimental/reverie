//! Coordinator RPC adapter for in-guest Reverie tools.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use std::io;
use std::path::Path;

use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Pid;
use reverie_preload::rpc::CoordinatorClient;
use reverie_preload::trap::raw_syscall6;

pub(crate) struct SpinMutex<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
}

impl<T> SpinMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub(crate) fn lock(&self) -> SpinGuard<'_, T> {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        SpinGuard { mutex: self }
    }
}

unsafe impl<T: Send> Sync for SpinMutex<T> {}

pub(crate) struct SpinGuard<'a, T> {
    mutex: &'a SpinMutex<T>,
}

impl<T> core::ops::Deref for SpinGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> core::ops::DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.held.store(false, Ordering::Release);
    }
}

// TODO-HUMAN-REVIEW(PR-127): Review blocking trusted-gate RPC semantics.
/// Blocking guest-side RPC handle backed by the shared preload wire protocol.
pub struct CoordinatorRpc<G: GlobalTool> {
    client: SpinMutex<CoordinatorClient>,
    config: G::Config,
    fd: libc::c_int,
    _global: PhantomData<fn() -> G>,
}

impl<G: GlobalTool> CoordinatorRpc<G> {
    pub(crate) const fn raw_fd(&self) -> libc::c_int {
        self.fd
    }

    /// Connect before installing seccomp and decode the coordinator config.
    pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
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
    unsafe {
        let _ = raw_syscall6(libc::SYS_exit_group, [status as u64, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}
