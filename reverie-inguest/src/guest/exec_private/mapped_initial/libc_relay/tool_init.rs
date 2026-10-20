//! Once-only trusted Tool startup on the SAME retained bootstrap relay.
//! No Guest, callback, lifecycle, Ready or global-control authority is created.
use super::super::MappedToolPrelude;
use super::*;
use crate::guest::event::SyscallDispatch;
use crate::guest::event::SyscallEvent;

const INPUT_RETIRED: u64 = u64::MAX;
const INPUT_RETIRING: u64 = u64::MAX - 1;

// A syscall-mediated change of the calling/return/protection domain belongs to
// the actual installer, using its raw gate and real success readbacks. This is
// not guest Linux policy. Do not feed these through ordinary trusted libc.
pub(super) fn changes_startup_domain(number: i64, args: [u64; 6]) -> bool {
    match number {
        libc::SYS_arch_prctl => !matches!(args[0], 0x1003 | 0x1004), // GET_FS/GET_GS only
        libc::SYS_modify_ldt
        | libc::SYS_prctl
        | libc::SYS_seccomp
        | libc::SYS_unshare
        | libc::SYS_setns
        | libc::SYS_rt_sigreturn
        | libc::SYS_rseq
        | libc::SYS_pkey_alloc
        | libc::SYS_pkey_free => true,
        _ => false,
    }
}
fn initial_phase(phase: u64, ready: u64, native_state: u64) -> bool {
    phase == 2 && ready == 0 && native_state == 1
}
pub(super) fn read(p: *const u64) -> u64 {
    // SAFETY: every private caller retains the actual initialized control owner.
    unsafe { p.read_volatile() }
}

// Called under the same busy exclusion, with authentic memory and sole leader.
// `in_handler` selects actual kernel mask/stack facts, not a synthetic context.
pub(super) unsafe fn verify_thread(s: &RelayState, p: &Progress, in_handler: bool) {
    let c = s.control.as_ptr();
    check(initial_phase(
        read(unsafe { &raw const (*c).phase }),
        read(unsafe { &raw const (*c).runtime_ready }),
        read(unsafe { &raw const (*c).native_state }),
    ));
    check(
        read(unsafe { &raw const (*c).abi_version }) == 1
            && read(unsafe { &raw const (*c).byte_len })
                == core::mem::size_of::<NativeControl>() as u64
            && read(unsafe { &raw const (*c).native_tid }) == s.tid as u64
            && read(unsafe { &raw const (*c).tool_fs }) == s.expected_private_fs
            && read(unsafe { &raw const (*c).bootstrap_handler })
                == bootstrap_sigsys as *const () as u64
            && read(unsafe { &raw const (*c).bootstrap_restorer }) == s.restorer as u64,
    );
    // Global publication is not needed for startup. If it exists, it must be
    // this exact same admitted control; never borrow another image's authority.
    let published = super::super::super::control_pointer();
    check(published.is_null() || published == c);
    check(
        unsafe { read_fs() } == s.expected_private_fs
            && unsafe { kernel(libc::SYS_gettid, [0; 6]) } == s.tid
            && unsafe { kernel(libc::SYS_getpid, [0; 6]) } == s.tid
            && unsafe { kernel(libc::SYS_brk, [0; 6]) } as u64
                == read(unsafe { &raw const (*c).kernel_brk }),
    );
    // One selected real frontend; the pre-libc path never reaches ToolInit.
    // Live SS_ONSTACK differs from the saved frame's uc_stack.flags==0.
    unsafe { super::frontend::verify_signal(s, p, in_handler) };
    let mut head = 0u64;
    let mut len = 0u64;
    check(
        unsafe {
            kernel(
                libc::SYS_get_robust_list,
                [0, (&raw mut head) as u64, (&raw mut len) as u64, 0, 0, 0],
            )
        } == 0
            && head == read(unsafe { &raw const (*c).private_robust_head })
            && len == 24
            && len == read(unsafe { &raw const (*c).private_robust_len })
            && read(unsafe { &raw const (*c).private_clear_tid }) == s.thread_list_lock,
    );
}

/// Enable only through the actual affine post-libc/adoption owner.
/// # Safety
/// All MappedToolPrelude::enable_tool_init physical/source obligations hold.
pub(in super::super) unsafe fn enable(owner: &MappedToolPrelude) -> Result<(), i32> {
    let raw = INSTALLED.load(Ordering::Acquire);
    if raw.is_null() {
        return Err(libc::EINVAL);
    }
    let busy = unsafe { &*(&raw const (*raw).busy) };
    if busy
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        die(REENTRY);
    }
    let s = unsafe { &*raw };
    let p = unsafe { &mut *s.progress.get() };
    check(
        s.control == owner.input.control && p.libc_cleaned && p.fs_set && p.tid_set && !p.tool_init,
    );
    check(
        crate::guest::tool_region::published_owner()
            .is_some_and(|r| core::ptr::eq(r, owner.region)),
    );
    let view = match p.tool_sites {
        Some(view) => view,
        None => die(INVALID),
    };
    let input_view = owner.input.scalar.view();
    check(
        view.bytes().as_ptr() == input_view.bytes().as_ptr()
            && view.bytes().len() == input_view.bytes().len()
            && view.address() == input_view.address(),
    );
    let rsp: usize;
    unsafe {
        core::arch::asm!("mov {}, rsp",out(reg)rsp,options(nomem,nostack,preserves_flags));
    }
    check(s.stack.covers(rsp, 1));
    unsafe { verify_thread(s, p, false) };
    let sites = super::super::scalar_value(view.table(8));
    check(!sites.is_empty() && sites.len() <= 4096);
    for i in 0..sites.len() {
        let post = super::super::scalar_value(sites.field(i, 0));
        // Safe decoder already proved sorted uniqueness and complete RX range.
        // Unsafe physical producer supplies actual instruction/source identity;
        // this byte comparison supplements that authority, never replaces it.
        check(unsafe { ((post - 2) as *const u16).read_unaligned() } == 0x050f);
    }
    let c = s.control.as_ptr();
    let fd = owner.input.input_fd;
    check(fd > 2 && read(unsafe { &raw const (*c).init_input_fd }) == fd as u64);
    check(s.input_identity.open && unsafe { fd_identity(i64::from(fd)) } == s.input_identity);
    let seals = unsafe {
        kernel(
            libc::SYS_fcntl,
            [fd as u64, libc::F_GET_SEALS as u64, 0, 0, 0, 0],
        )
    };
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    check(seals >= 0 && seals & i64::from(required) == i64::from(required));
    p.tool_init = true;
    s.busy.store(false, Ordering::Release);
    Ok(())
}

/// Forward only after authentic bootstrap-prefix checks and the same exclusion.
/// # Safety
/// `frame` is this invocation's actual exclusive kernel frame, with saved RSP
/// already in s.stack, handler RSP in the selected actual owned altstack,
/// exact selected mask and sole leader.
pub(super) unsafe fn forward(s: &RelayState, p: &mut Progress, frame: &mut BootstrapPrefix<'_>) {
    check(p.libc_cleaned && p.tool_init);
    unsafe { verify_thread(s, p, true) };
    let view = match p.tool_sites {
        Some(view) => view,
        None => die(INVALID),
    };
    let sites = super::super::scalar_value(view.table(8));
    let post = frame.rip();
    let mut selected = false;
    for i in 0..sites.len() {
        selected |= super::super::scalar_value(sites.field(i, 0)) == post;
    }
    check(
        selected && post >= 2 && unsafe { ((post - 2) as *const u16).read_unaligned() } == 0x050f,
    );
    let number = frame.rax() as i64;
    let args = frame.args();
    // x32 never shares this qualified x86-64 ABI. Process/signal/registration
    // control uses the SAME existing nested-Tool refusal inventory; failure
    // terminates startup rather than inventing an acknowledged guest result.
    if frame.rax() & 0x4000_0000 != 0
        || crate::guest::trap_dispatch::nested_tool_control_result(number, true).is_some()
        || changes_startup_domain(number, args)
    {
        die(OPERATION);
    }
    let c = s.control.as_ptr();
    let input = read(unsafe { &raw const (*c).init_input_fd });
    let extra = if input == INPUT_RETIRED {
        None
    } else {
        check(input == super::super::scalar_value(view.scalar(5)) && input <= i32::MAX as u64);
        Some(input)
    };
    // Numeric guard carrier only. Never dispatch a Guest, callback, continuation
    // or event.forward(): physical execution below uses the actual Tool gate.
    let mut event = SyscallEvent {
        number,
        args,
        instruction_pointer: post - 2,
        result: 0,
        context: 0,
        dispatch: SyscallDispatch::Trap,
        guest_pkru: None,
    };
    let guarded =
        unsafe { crate::guest::protect::protect_tool_init_descriptors(&mut event, extra) };
    let result = if guarded {
        event.result
    } else if let Some(result) = crate::guest::restorer::owner_mapping_change_result(number, args) {
        result
    } else {
        unsafe { kernel(number, args) }
    };
    // Only RAX changes. No registration/FS/mask/selector repair or emulated
    // success: installers must make those changes through their real raw gate.
    unsafe { verify_thread(s, p, true) };
    frame.set_result(result);
}

/// Consume the actual child input lease inside the already armed fatal guard.
/// # Safety
/// Accepted genuine InitialImage client and exact physical owner; any error is
/// terminal under that same fatal guard, before publication or fallible drop.
pub(in super::super) unsafe fn retire_input(owner: &MappedToolPrelude) -> Result<(), i32> {
    let raw = INSTALLED.load(Ordering::Acquire);
    if raw.is_null() {
        return Err(libc::EINVAL);
    }
    let busy = unsafe { &*(&raw const (*raw).busy) };
    if busy
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        die(REENTRY);
    }
    let s = unsafe { &*raw };
    let p = unsafe { &mut *s.progress.get() };
    check(s.control == owner.input.control && p.libc_cleaned && p.tool_init);
    unsafe { verify_thread(s, p, false) };
    let c = s.control.as_ptr();
    let fd = owner.input.input_fd;
    check(
        fd > 2
            && read(unsafe { &raw const (*c).init_input_fd }) == fd as u64
            && unsafe { fd_identity(i64::from(fd)) } == s.input_identity,
    );
    // Spend retry authority BEFORE the actual close. Failure, including EINTR,
    // retains RETIRING and last_result; it can never look like confirmed close.
    unsafe { (&raw mut (*c).init_input_fd).write_volatile(INPUT_RETIRING) };
    p.last_nr = libc::SYS_close as u64;
    let result = unsafe { kernel(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    p.last_result = result;
    if result != 0 {
        s.busy.store(false, Ordering::Release);
        return Err(if (-4095..0).contains(&result) {
            (-result) as i32
        } else {
            libc::EIO
        });
    }
    unsafe { (&raw mut (*c).init_input_fd).write_volatile(INPUT_RETIRED) };
    check(
        unsafe {
            kernel(
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
            )
        } == -i64::from(libc::EBADF),
    );
    s.busy.store(false, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tool_init_is_not_ready_callback_or_successor_authority() {
        assert!(initial_phase(2, 0, 1));
        for (phase, ready, state) in [
            (1, 0, 1),
            (2, 1, 1),
            (3, 1, 1),
            (4, 1, 1),
            (6, 0, 1),
            (2, 0, 0),
        ] {
            assert!(!initial_phase(phase, ready, state));
        }
    }
    #[test]
    fn trusted_startup_queries_do_not_authorize_setters_or_process_creation() {
        assert!(!changes_startup_domain(
            libc::SYS_arch_prctl,
            [0x1003, 0, 0, 0, 0, 0]
        ));
        assert!(changes_startup_domain(
            libc::SYS_arch_prctl,
            [0x1002, 0, 0, 0, 0, 0]
        ));
        for nr in [
            libc::SYS_rt_sigreturn,
            libc::SYS_seccomp,
            libc::SYS_unshare,
            libc::SYS_prctl,
        ] {
            assert!(changes_startup_domain(nr, [0; 6]));
        }
        for nr in [
            libc::SYS_clone,
            libc::SYS_execve,
            libc::SYS_rt_sigprocmask,
            libc::SYS_set_tid_address,
            libc::SYS_set_robust_list,
        ] {
            assert!(crate::guest::trap_dispatch::nested_tool_control_result(nr, true).is_some());
        }
        for nr in [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_getrandom,
            libc::SYS_recvmsg,
        ] {
            assert!(crate::guest::trap_dispatch::nested_tool_control_result(nr, true).is_none());
            assert!(!changes_startup_domain(nr, [0; 6]));
        }
    }
}
