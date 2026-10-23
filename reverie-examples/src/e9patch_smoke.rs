//! Narrow generic-Tool proof shared by the e9patch preload and test harness.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

// TODO-HUMAN-REVIEW(PR-269): Review the public
// concrete-tool fixture shared across the preload/coordinator boundary.
/// Coordinator-owned count of direct AOT Tool callbacks.
#[derive(Default)]
pub struct AotCounterGlobal {
    delivered: AtomicU64,
}

impl AotCounterGlobal {
    /// Returns the number of callbacks recorded through `GlobalRPC`.
    pub fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::SeqCst)
    }
}

#[reverie::global_tool]
impl GlobalTool for AotCounterGlobal {
    type Request = u64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, amount: u64) {
        self.delivered.fetch_add(amount, Ordering::SeqCst);
    }
}

// TODO-HUMAN-REVIEW(PR-269): Review the public
// concrete-tool fixture shared across the preload/coordinator boundary.
/// Tool that RPC-counts and emulates a direct `getpid` syscall.
#[derive(Default)]
pub struct AotCounterTool;

// TODO-HUMAN-REVIEW(PR-269): Review the direct getpid
// callback, register mutation proof, coordinator RPC, and emulated result.
#[reverie::tool]
impl Tool for AotCounterTool {
    type GlobalState = AotCounterGlobal;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        let mut regs = guest.regs().await;
        assert_ne!(regs.rip, 0);
        assert_eq!(regs.orig_rax, Sysno::getpid.id() as u64);
        regs.r10 = 0x0e9a_7c40_5eed;
        guest.set_regs(regs).await?;
        assert_eq!(guest.regs().await.r10, 0x0e9a_7c40_5eed);
        guest.send_rpc(1).await;
        Ok(424_242)
    }
}
