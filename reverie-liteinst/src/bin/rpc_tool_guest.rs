use core::arch::global_asm;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie_rpc_transport::RpcServer;

const CALLS: u64 = 32;
static LAST_TOTAL: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct CounterGlobal {
    calls: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = u64;
    type Response = u64;
    type Config = ();

    async fn receive_rpc(&self, _from: reverie::Tid, amount: u64) -> u64 {
        self.calls.fetch_add(amount, Ordering::Relaxed) + amount
    }
}

#[derive(Default)]
struct CounterTool;

#[reverie::tool]
impl Tool for CounterTool {
    type GlobalState = CounterGlobal;
    type ThreadState = u64;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        *guest.thread_state_mut() += 1;
        let total = guest.send_rpc(1).await;
        LAST_TOTAL.store(total, Ordering::Relaxed);
        Ok(guest.inject(syscall).await?)
    }
}

global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_liteinst_rpc_getpid
    .hidden reverie_liteinst_rpc_getpid
    .type reverie_liteinst_rpc_getpid,@function
reverie_liteinst_rpc_getpid:
    mov eax, 39
    .global reverie_liteinst_rpc_getpid_site
    .hidden reverie_liteinst_rpc_getpid_site
reverie_liteinst_rpc_getpid_site:
    syscall
    nop
    nop
    nop
    ret
    .size reverie_liteinst_rpc_getpid, .-reverie_liteinst_rpc_getpid
"#
);

unsafe extern "C" {
    fn reverie_liteinst_rpc_getpid() -> i64;
    static reverie_liteinst_rpc_getpid_site: u8;
}

fn coordinator(path: &Path) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    runtime.block_on(async {
        let server = RpcServer::bind(path, Arc::new(CounterGlobal::default()), ()).unwrap();
        println!("ready");
        std::io::stdout().flush().unwrap();
        server.serve().await.unwrap();
    });
}

fn guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let mut pid = None;
    for _ in 0..CALLS {
        let observed = unsafe { reverie_liteinst_rpc_getpid() };
        assert_eq!(*pid.get_or_insert(observed), observed);
    }
    let address = core::ptr::addr_of!(reverie_liteinst_rpc_getpid_site) as usize as u64;
    let traps = reverie_liteinst::reverie_liteinst_site_trap_count(address);
    let hooks = reverie_liteinst::reverie_liteinst_site_hook_count(address);
    let rpc = LAST_TOTAL.load(Ordering::Relaxed);
    println!("calls={CALLS} traps={traps} hooks={hooks} rpc={rpc}");
    assert_eq!(traps, 1);
    assert_eq!(hooks, CALLS);
    assert!(rpc >= CALLS);
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let mode = args.next().expect("mode");
    let path = args.next().expect("socket path");
    match mode.to_str() {
        Some("coordinator") => coordinator(Path::new(&path)),
        Some("guest") => guest(Path::new(&path)),
        _ => panic!("expected coordinator or guest"),
    }
}
