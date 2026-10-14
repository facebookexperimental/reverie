//! Real installed-owner controls, reached through the existing lifecycle binary.

use std::io::Write;

use serde::ser::SerializeStruct;

use super::*;

static REENTRY_CHECKS: AtomicU64 = AtomicU64::new(0);
static TOOL_ADDRESS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, serde::Deserialize)]
struct SharedRequest {
    tag: u64,
    reenter: bool,
}

impl serde::Serialize for SharedRequest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.reenter {
            // Actual request encoding runs while CoordinatorRpc holds its real
            // connection SpinGuard. Both accessors must refuse without sending.
            for result in [
                reverie_liteinst::blocking_global_rpc::<SharedGlobal>(Self {
                    tag: 9001,
                    reenter: false,
                }),
                reverie_inguest::guest::installed_tool::blocking_global_rpc::<SharedGlobal>(Self {
                    tag: 9002,
                    reenter: false,
                }),
            ] {
                if !result.is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock) {
                    return Err(serde::ser::Error::custom(
                        "actual RPC reentry was not WouldBlock",
                    ));
                }
                REENTRY_CHECKS.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut fields = serializer.serialize_struct("SharedRequest", 2)?;
        fields.serialize_field("tag", &self.tag)?;
        fields.serialize_field("reenter", &self.reenter)?;
        fields.end()
    }
}

#[derive(Default)]
struct SharedGlobal {
    requests: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for SharedGlobal {
    type Request = SharedRequest;
    type Response = (i32, u64, u64);
    type Config = ();

    async fn receive_rpc(&self, from: Tid, request: SharedRequest) -> (i32, u64, u64) {
        let count = self.requests.fetch_add(1, Ordering::Relaxed) + 1;
        (from.as_raw(), count, request.tag)
    }
}

#[derive(Default)]
struct SharedTool {
    callbacks: AtomicU64,
}

#[reverie::tool]
impl Tool for SharedTool {
    type GlobalState = SharedGlobal;
    type ThreadState = u64;

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        let address = core::ptr::from_ref(self) as usize;
        let _ = TOOL_ADDRESS.compare_exchange(0, address, Ordering::Relaxed, Ordering::Relaxed);
        assert_eq!(TOOL_ADDRESS.load(Ordering::Relaxed), address);
        let count = self.callbacks.fetch_add(1, Ordering::Relaxed) + 1;
        *guest.thread_state_mut() += 1;
        assert_eq!(*guest.thread_state(), count);
        assert!(count <= 2, "unexpected extra callback");

        let source = guest.tid().as_raw();
        let legacy = reverie_liteinst::blocking_global_rpc::<SharedGlobal>(SharedRequest {
            tag: 1000 + count,
            reenter: false,
        })
        .unwrap();
        let shared = reverie_inguest::guest::installed_tool::blocking_global_rpc::<SharedGlobal>(
            SharedRequest {
                tag: 2000 + count,
                reenter: false,
            },
        )
        .unwrap();
        assert_eq!(legacy, (source, 3 * count - 2, 1000 + count));
        assert_eq!(shared, (source, 3 * count - 1, 2000 + count));

        for refusal in [
            reverie_liteinst::blocking_global_rpc::<UnusedGlobal>(6001),
            reverie_inguest::guest::installed_tool::blocking_global_rpc::<UnusedGlobal>(6002),
        ] {
            assert!(refusal.is_err_and(|error| error.kind() == std::io::ErrorKind::InvalidInput));
        }
        if count == 1 {
            let outer =
                reverie_inguest::guest::installed_tool::blocking_global_rpc::<SharedGlobal>(
                    SharedRequest {
                        tag: 3001,
                        reenter: true,
                    },
                )
                .unwrap();
            assert_eq!(outer, (source, 3, 3001));
            assert_eq!(REENTRY_CHECKS.load(Ordering::Relaxed), 2);
        }
        Ok(4100 + count as i64)
    }
}

pub(super) fn run(duplicate: bool) {
    let coordinator =
        std::env::var_os(reverie_liteinst::COORDINATOR_ENV).expect("actual launcher coordinator");
    let coordinator = std::path::PathBuf::from(coordinator);
    // SAFETY: the real fixture starts before application-created threads and
    // uses the existing complete installer with its declared scoped allocator.
    unsafe { reverie_liteinst::install_tool_quiescent::<SharedTool>(&coordinator) }.unwrap();

    // Actual guest syscall sites, with genuine saved-frame/guard provenance.
    assert_eq!(unsafe { reverie_liteinst_lifecycle_getpid() }, 4101);
    assert_eq!(unsafe { reverie_liteinst_lifecycle_getpid() }, 4102);
    assert_eq!(REENTRY_CHECKS.load(Ordering::Relaxed), 2);
    println!(
        "shared handler: callbacks=2 owner=stable LI=2 shared=2 wrong-global=4 reentry=2 outer=1"
    );
    std::io::stdout().flush().unwrap();
    if duplicate {
        // First-owner observations are complete before the terminal attempt.
        // The inherited-filter guard may refuse before registry publication;
        // this control does not claim to reach the registry duplicate branch.
        unsafe { reverie_liteinst::install_tool_quiescent::<SharedTool>(&coordinator) }.unwrap();
        panic!("whole duplicate installation returned");
    }
}
