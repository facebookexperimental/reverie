//! Actual public installer controls. The static Tool role, not the two false
//! configuration flags, determines this fixture's operational admission.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::ToolStreamRole;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_rpc_transport::RpcServer;
use serde::Deserialize;
use serde::Serialize;

const REFUSAL_STATUS: i32 = 78;
static ADMISSIONS: AtomicUsize = AtomicUsize::new(0);
static CONSTRUCTIONS: AtomicUsize = AtomicUsize::new(0);
static STARTS: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    record_mode: bool,
    replay_mode: bool,
    coordinator_marker: u64,
}

#[derive(Default)]
struct Global;

#[reverie::global_tool]
impl GlobalTool for Global {
    type Config = Config;
    type Request = ();
    type Response = ();

    async fn receive_rpc(&self, _from: Pid, _request: ()) {}
}

fn check_config(config: &Config) {
    assert!(!config.record_mode);
    assert!(!config.replay_mode);
    assert_eq!(config.coordinator_marker, 0x63ad_1198);
}

#[derive(Default)]
struct AdmissionTool<const ROLE: u8>;

#[reverie::tool]
impl<const ROLE: u8> Tool for AdmissionTool<ROLE> {
    type GlobalState = Global;
    type ThreadState = ();

    fn stream_role() -> ToolStreamRole {
        match ROLE {
            0 => ToolStreamRole::Unknown,
            1 => ToolStreamRole::Plain,
            2 => ToolStreamRole::BinaryRecord,
            3 => ToolStreamRole::BinaryReplay,
            _ => panic!("unexpected fixture role"),
        }
    }

    fn facility_admission(config: &Config) -> Result<(), Error> {
        check_config(config);
        assert_eq!(ADMISSIONS.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(CONSTRUCTIONS.load(Ordering::SeqCst), 0);
        assert_eq!(STARTS.load(Ordering::SeqCst), 0);
        if Self::stream_role() != ToolStreamRole::Plain {
            // The Tool owns its named refusal and status. Exiting here also
            // exercises the pre-publication boundary with fixed gates enabled;
            // this is not a backend-selected errno or recovery path.
            println!(
                "facility refused: role={:?} modes=false,false admission=1 new=0 start=0",
                Self::stream_role()
            );
            std::io::stdout().flush().unwrap();
            std::process::exit(REFUSAL_STATUS);
        }
        Ok(())
    }

    fn subscriptions(_config: &Config) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    fn new(_pid: Pid, config: &Config) -> Self {
        check_config(config);
        assert_eq!(ADMISSIONS.load(Ordering::SeqCst), 1);
        assert_eq!(CONSTRUCTIONS.fetch_add(1, Ordering::SeqCst), 0);
        Self
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        check_config(guest.config());
        assert_eq!(CONSTRUCTIONS.load(Ordering::SeqCst), 1);
        assert_eq!(STARTS.fetch_add(1, Ordering::SeqCst), 0);
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        assert_eq!(STARTS.load(Ordering::SeqCst), 1);
        CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(guest.inject(syscall).await?)
    }
}

pub(super) fn coordinator(path: &Path) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    runtime.block_on(async {
        let config = Config {
            record_mode: false,
            replay_mode: false,
            coordinator_marker: 0x63ad_1198,
        };
        RpcServer::bind(path, Arc::new(Global), config)
            .unwrap()
            .serve()
            .await
            .unwrap();
    });
}

fn install<const ROLE: u8>(path: &Path, installer: &str) {
    let pid = i64::from(std::process::id());
    let result = match installer {
        "shared" => unsafe {
            reverie_inguest::guest::tool_install::install_tool_with::<AdmissionTool<ROLE>, _>(
                path,
                true,
                reverie_inguest::guest::tool_install::TrapHost::new(Default::default()),
            )
        },
        "liteinst" => unsafe { reverie_liteinst::install_tool::<AdmissionTool<ROLE>>(path) },
        "quiescent" => unsafe {
            reverie_liteinst::install_tool_quiescent::<AdmissionTool<ROLE>>(path)
        },
        "bootstrap" => unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<AdmissionTool<ROLE>>(path)
        },
        _ => panic!("unknown installer"),
    };
    result.unwrap();
    // No test-only direct hook call: the installed runtime must deliver this
    // actual guest syscall and its lazy thread-start callback to the Tool.
    assert_eq!(unsafe { super::reverie_liteinst_rpc_getpid() }, pid);
    assert_eq!(ADMISSIONS.load(Ordering::SeqCst), 1);
    assert_eq!(CONSTRUCTIONS.load(Ordering::SeqCst), 1);
    assert_eq!(STARTS.load(Ordering::SeqCst), 1);
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    println!("facility plain: modes=false,false admission=1 new=1 start=1 syscall=1");
    std::io::stdout().flush().unwrap();
}

pub(super) fn run(path: &Path, installer: &str, role: &str) {
    match role {
        "unknown" => install::<0>(path, installer),
        "plain" => install::<1>(path, installer),
        "record" => install::<2>(path, installer),
        "replay" => install::<3>(path, installer),
        _ => panic!("unknown role"),
    }
}
