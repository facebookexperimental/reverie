use core::arch::global_asm;
use std::ffi::CStr;

const CALLS: u64 = 32;

global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_liteinst_fixed_getpid
    .hidden reverie_liteinst_fixed_getpid
    .type reverie_liteinst_fixed_getpid,@function
reverie_liteinst_fixed_getpid:
    mov eax, 39
    .global reverie_liteinst_fixed_getpid_site
    .hidden reverie_liteinst_fixed_getpid_site
reverie_liteinst_fixed_getpid_site:
    syscall
    nop
    nop
    nop
    ret
    .size reverie_liteinst_fixed_getpid, .-reverie_liteinst_fixed_getpid
"#
);

unsafe extern "C" {
    fn reverie_liteinst_fixed_getpid() -> i64;
    static reverie_liteinst_fixed_getpid_site: u8;
}

type CountFn = unsafe extern "C" fn(u64) -> u64;

unsafe fn count_function(name: &CStr) -> CountFn {
    // SAFETY: RTLD_DEFAULT searches already loaded DSOs and name is terminated.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    assert!(!symbol.is_null(), "missing preload counter export");
    // SAFETY: both exported counter symbols have this exact C ABI.
    unsafe { core::mem::transmute(symbol) }
}

fn main() {
    let mut expected = None;
    for _ in 0..CALLS {
        // SAFETY: the assembly function preserves the C ABI and returns getpid.
        let observed = unsafe { reverie_liteinst_fixed_getpid() };
        assert_eq!(*expected.get_or_insert(observed), observed);
    }

    let address = core::ptr::addr_of!(reverie_liteinst_fixed_getpid_site) as usize as u64;
    // SAFETY: names and exported function signatures are fixed by the runtime.
    let traps = unsafe { count_function(c"reverie_liteinst_site_trap_count")(address) };
    // SAFETY: names and exported function signatures are fixed by the runtime.
    let hooks = unsafe { count_function(c"reverie_liteinst_site_hook_count")(address) };
    println!("calls={CALLS} traps={traps} hooks={hooks}");
    assert_eq!(traps, 1);
    assert_eq!(hooks, CALLS);
}
