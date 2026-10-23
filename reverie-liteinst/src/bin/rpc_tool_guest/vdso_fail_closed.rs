//! LiteInst coverage for the fail-closed vDSO patch.
//!
//! The x86_64 vDSO exports `__vdso_sgx_enter_enclave` on kernels built with
//! SGX support. It has no syscall equivalent and no backend listed it, so it
//! stayed native. The patch now covers every entry point the vDSO exports:
//! once a Tool observing any syscall is installed, this one returns -ENOSYS.

use std::path::Path;

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;

const SYMBOL: &core::ffi::CStr = c"__vdso_sgx_enter_enclave";

/// Observes one syscall that has no vDSO fast path.
#[derive(Default)]
struct OpenatTool;

#[reverie::tool]
impl Tool for OpenatTool {
    type GlobalState = super::CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        [Sysno::openat].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        Ok(guest.inject(syscall).await?)
    }
}

type SgxEnterEnclave = unsafe extern "C" fn(
    rdi: libc::c_ulong,
    rsi: libc::c_ulong,
    rdx: libc::c_ulong,
    function: libc::c_uint,
    r8: libc::c_ulong,
    r9: libc::c_ulong,
    run: *mut libc::c_void,
) -> libc::c_int;

fn resolve() -> Option<SgxEnterEnclave> {
    let vdso = unsafe {
        libc::dlopen(
            c"linux-vdso.so.1".as_ptr(),
            libc::RTLD_NOW | libc::RTLD_NOLOAD,
        )
    };
    if vdso.is_null() {
        return None;
    }
    let symbol = unsafe { libc::dlsym(vdso, SYMBOL.as_ptr()) };
    (!symbol.is_null())
        .then(|| unsafe { core::mem::transmute::<*mut libc::c_void, SgxEnterEnclave>(symbol) })
}

/// Calls SGX enclave entry with leaf 0, which is neither EENTER nor ERESUME.
fn call_invalid_leaf(sgx: SgxEnterEnclave) -> libc::c_int {
    unsafe { sgx(0, 0, 0, 0, 0, 0, core::ptr::null_mut()) }
}

pub(crate) fn run(path: &Path) {
    let Some(sgx) = resolve() else {
        println!("vdso-sgx=absent");
        return;
    };
    assert_eq!(
        call_invalid_leaf(sgx),
        -libc::EINVAL,
        "native SGX entry rejects leaf 0"
    );

    unsafe { reverie_liteinst::install_tool::<OpenatTool>(path) }.unwrap();

    assert_eq!(
        call_invalid_leaf(sgx),
        -libc::ENOSYS,
        "patched SGX entry must return -ENOSYS"
    );
    println!("vdso-sgx=stubbed");
}
