//! Private actual-controller join. Facts borrow the one installed host/region;
//! no address supplied by a caller, parser or ready bit can construct them.
use super::*;
use crate::guest::exec_private::InitialImageControl;
use crate::guest::tool_region::ToolRegion;

#[derive(Clone, Copy)]
pub(super) enum Frontend {
    Bootstrap,
    Replacing,
    Installed(InstalledFacts),
    // The startup path still refuses retirement. Only the actual Running
    // continuation can borrow these same immutable installed-owner facts.
    Retired(InstalledFacts),
}
#[derive(Clone, Copy)]
pub(super) struct InstalledFacts {
    // The actual published stable host is bound once before controller install.
    // No pointer/reference to the movable InitialImageControl is retained.
    host: usize,
    region: &'static ToolRegion,
    signal: FrameFacts,
    reserved: u64,
}
#[derive(Clone, Copy)]
pub(super) struct FrameFacts {
    pub(super) stack: Extent,
    pub(super) mask: u64,
    pub(super) restorer: usize,
    handler: u64,
}

fn handler_flags() -> u64 {
    (libc::SA_SIGINFO | libc::SA_ONSTACK | crate::signal::SA_RESTORER) as u64
}
fn ordinary_mask(reserved: u64) -> u64 {
    !(reserved | (1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1)))
}
fn eligible_phase(phase: u64, ready: u64, state: u64) -> bool {
    phase == 2 && ready == 0 && state == 1
}
fn checked_registered_stack(
    bottom: usize,
    top: usize,
    actual_bottom: usize,
    actual_size: u64,
    actual_flags: i32,
    in_handler: bool,
) -> bool {
    top.checked_sub(bottom)
        .is_some_and(|size| size != 0 && size as u64 == actual_size)
        && actual_bottom == bottom
        && actual_flags == if in_handler { libc::SS_ONSTACK } else { 0 }
}

// Select BEFORE reading any context prefix or applying the bootstrap-only
// altstack/mask checks. Replacement and retirement never authorize a frame.
pub(super) fn frame_facts(s: &RelayState, p: &Progress) -> FrameFacts {
    match p.frontend {
        Frontend::Bootstrap => FrameFacts {
            stack: s.altstack,
            mask: s.startup_mask,
            restorer: s.restorer,
            handler: bootstrap_sigsys as *const () as u64,
        },
        Frontend::Installed(facts) => {
            check(p.libc_cleaned && p.tool_init && facts.host != 0);
            let c = s.control.as_ptr();
            check(eligible_phase(
                tool_init::read(unsafe { &raw const (*c).phase }),
                tool_init::read(unsafe { &raw const (*c).runtime_ready }),
                tool_init::read(unsafe { &raw const (*c).native_state }),
            ));
            check(super::super::super::control_pointer() == c);
            check(
                crate::guest::tool_region::published_owner()
                    .is_some_and(|region| core::ptr::eq(region, facts.region)),
            );
            let registered = facts.region.registered_alternate_stack();
            check(registered.is_some_and(|stack| {
                stack.bottom == facts.signal.stack.lo && stack.top == facts.signal.stack.hi
            }));
            check(crate::trap::has_dispatcher() && crate::trap::signal_return_restricted());
            check(crate::guest::signal::reserved_signal_mask() == facts.reserved);
            facts.signal
        }
        Frontend::Replacing | Frontend::Retired(_) => die(INVALID),
    }
}

// Raw queries only: safe inside an authentic SIGSYS frame as well as immediately
// after replacement. The saved frame stack flags are checked separately by
// BootstrapPrefix; live sigaltstack MUST report SS_ONSTACK inside the handler.
pub(super) unsafe fn verify_signal(s: &RelayState, p: &Progress, in_handler: bool) {
    let facts = frame_facts(s, p);
    let reserved = match p.frontend {
        Frontend::Installed(installed) => Some(installed.reserved),
        _ => None,
    };
    unsafe { verify_signal_facts(facts, reserved, in_handler) };
}

// The caller has already selected an authentic owner and its exact mask.
unsafe fn verify_signal_facts(facts: FrameFacts, reserved: Option<u64>, in_handler: bool) {
    let mut mask = 0_u64;
    check(
        unsafe {
            kernel(
                libc::SYS_rt_sigprocmask,
                [libc::SIG_SETMASK as u64, 0, (&raw mut mask) as u64, 8, 0, 0],
            )
        } == 0
            && mask
                == (facts.mask
                    | if in_handler {
                        1_u64 << (libc::SIGSYS - 1)
                    } else {
                        0
                    }),
    );
    let mut action = KernelSigaction::default();
    check(
        unsafe {
            kernel(
                libc::SYS_rt_sigaction,
                [libc::SIGSYS as u64, 0, (&raw mut action) as u64, 8, 0, 0],
            )
        } == 0
            && action.handler == facts.handler
            && action.restorer == facts.restorer as u64
            && action.flags == handler_flags()
            && action.mask == 0,
    );
    let mut stack = KernelStack {
        ss_sp: ptr::null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    check(
        unsafe {
            kernel(
                libc::SYS_sigaltstack,
                [0, (&raw mut stack) as u64, 0, 0, 0, 0],
            )
        } == 0
            && checked_registered_stack(
                facts.stack.lo,
                facts.stack.hi,
                stack.ss_sp as usize,
                stack.ss_size,
                stack.ss_flags,
                in_handler,
            ),
    );
    if let Some(reserved) = reserved {
        // Instruction handlers are installed before the controller replaces
        // SIGSYS; both dispositions must remain the actual qualified bridges.
        if reserved & (1_u64 << (libc::SIGSEGV - 1)) != 0 {
            let mut instruction = KernelSigaction::default();
            check(
                unsafe {
                    kernel(
                        libc::SYS_rt_sigaction,
                        [
                            libc::SIGSEGV as u64,
                            0,
                            (&raw mut instruction) as u64,
                            8,
                            0,
                            0,
                        ],
                    )
                } == 0
                    && instruction.handler
                        == crate::guest::exec_private::signal_entry(
                            true,
                            crate::trap::pkru_present(),
                        ) as *const () as u64
                    && instruction.restorer == facts.restorer as u64
                    && instruction.flags == handler_flags()
                    && instruction.mask == 0,
            );
        }
    }
}

// The sole entry is the actual InitialImageController, after its existing
// configuration/bootstrap checks. A null relay means the unchanged legacy
// origin; a present relay must join this exact admitted control or terminate.
// Preparations can allocate/trap; they finish BEFORE the exclusive replacement
// interval. No initialized flag or safe scalar API can select Installed mode.
/// Join only from the actual live initial frontend controller.
///
/// # Safety
/// Caller is that live controller with its real stable bound ToolHost, the same
/// admitted control and published ToolRegion, and the sole initial native leader.
/// The installed retained relay and all physical host-owned extents remain live.
pub(in crate::guest::exec_private) unsafe fn install_if_mapped(
    owner: &InitialImageControl,
    region: &'static ToolRegion,
) -> std::io::Result<bool> {
    let raw = INSTALLED.load(Ordering::Acquire);
    if raw.is_null() {
        return Ok(false);
    }
    // SAFETY: INSTALLED remains retained for this physical image generation.
    check(unsafe { (*raw).control.as_ptr() } as usize == owner.control);
    let prepared = crate::trap::prepare_handler()?;
    let lease = region.stack(libc::SIGSTKSZ.max(64 * 1024))?;
    let stack_extent = Extent {
        lo: lease.base(),
        hi: lease.top(),
    };
    let busy = unsafe { &*(&raw const (*raw).busy) };
    if busy
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        die(REENTRY);
    }
    let s = unsafe { &*raw };
    let p = unsafe { &mut *s.progress.get() };
    check(matches!(p.frontend, Frontend::Bootstrap) && p.libc_cleaned && p.tool_init);
    check(
        owner.installation.load(Ordering::Acquire) == 1
            && owner.lifecycle.load(Ordering::Acquire) == 0,
    );
    let host = owner.installed_host.load(Ordering::Acquire);
    check(host != 0 && super::super::super::control_pointer() == s.control.as_ptr());
    check(
        crate::guest::tool_region::published_owner().is_some_and(|r| core::ptr::eq(r, region))
            && region.registered_alternate_stack().is_none()
            && lease.belongs_to(region),
    );
    unsafe { tool_init::verify_thread(s, p, false) };
    check(
        prepared.entry() as *const () as u64
            == crate::guest::exec_private::signal_entry(false, crate::trap::pkru_present())
                as *const () as u64,
    );
    let reserved = crate::guest::signal::reserved_signal_mask();
    check(reserved & (1_u64 << (libc::SIGSYS - 1)) != 0);
    let ordinary = ordinary_mask(reserved);
    // Publish the refusing state before the FIRST actual kernel mutation. The
    // same busy guard remains held through every query and immutable fact store.
    p.frontend = Frontend::Replacing;
    let stack = KernelStack {
        ss_sp: stack_extent.lo as *mut c_void,
        ss_flags: 0,
        ss_size: (stack_extent.hi - stack_extent.lo) as u64,
    };
    check(
        unsafe {
            kernel(
                libc::SYS_sigaltstack,
                [(&raw const stack) as u64, 0, 0, 0, 0, 0],
            )
        } == 0,
    );
    // Once registered, the real kernel owns a live pointer. Retain the entire
    // lease even on any subsequent terminal failure; never RAII-unmap it.
    core::mem::forget(lease);
    unsafe { region.publish_registered_altstack(stack_extent.lo, stack.ss_size as usize) };
    let action = KernelSigaction {
        handler: prepared.entry() as *const () as u64,
        flags: handler_flags(),
        restorer: crate::trap::FIXED_SIGNAL_RESTORER_ENTRY,
        mask: 0,
    };
    check(
        unsafe {
            kernel(
                libc::SYS_rt_sigaction,
                [libc::SIGSYS as u64, (&raw const action) as u64, 0, 8, 0, 0],
            )
        } == 0,
    );
    crate::trap::set_signal_return_restricted();
    check(
        unsafe {
            kernel(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_UNBLOCK as u64,
                    (&raw const reserved) as u64,
                    0,
                    8,
                    0,
                    0,
                ],
            )
        } == 0,
    );
    // No fallible I/O/error construction, allocator, procfs or ordinary libc
    // calls occur between Replacing and these exact actual kernel readbacks.
    let mut observed_action = KernelSigaction::default();
    let mut observed_stack = KernelStack {
        ss_sp: ptr::null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    let mut observed_mask = 0_u64;
    check(
        unsafe {
            kernel(
                libc::SYS_rt_sigaction,
                [
                    libc::SIGSYS as u64,
                    0,
                    (&raw mut observed_action) as u64,
                    8,
                    0,
                    0,
                ],
            )
        } == 0
            && observed_action == action,
    );
    check(
        unsafe {
            kernel(
                libc::SYS_sigaltstack,
                [0, (&raw mut observed_stack) as u64, 0, 0, 0, 0],
            )
        } == 0
            && checked_registered_stack(
                stack_extent.lo,
                stack_extent.hi,
                observed_stack.ss_sp as usize,
                observed_stack.ss_size,
                observed_stack.ss_flags,
                false,
            ),
    );
    check(
        unsafe {
            kernel(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    0,
                    (&raw mut observed_mask) as u64,
                    8,
                    0,
                    0,
                ],
            )
        } == 0
            && observed_mask == ordinary,
    );
    check(
        owner.installed_host.load(Ordering::Acquire) == host
            && owner.installation.load(Ordering::Acquire) == 1
            && owner.lifecycle.load(Ordering::Acquire) == 0,
    );
    // These are the existing actual controller publications, not a second
    // owner/Ready route. The facts contain only immutable stable owner borrows.
    owner
        .region
        .store(core::ptr::from_ref(region).cast_mut(), Ordering::Release);
    owner.installation.store(2, Ordering::Release);
    p.frontend = Frontend::Installed(InstalledFacts {
        host,
        region,
        reserved,
        signal: FrameFacts {
            stack: stack_extent,
            mask: ordinary,
            handler: action.handler,
            restorer: action.restorer as usize,
        },
    });
    unsafe { tool_init::verify_thread(s, p, false) };
    s.busy.store(false, Ordering::Release);
    Ok(true)
}

// Called ONLY by the same owner's finish after genuine lifecycle completion
// and existing final readbacks, immediately BEFORE its real ready=1 store.
/// Retire only at the actual initial owner finish boundary.
///
/// # Safety
/// Live actual InitialImageControl and same admitted physical owner, after real
/// lifecycle completion and final frontend verification, before Ready publication.
pub(in crate::guest::exec_private) unsafe fn retire_if_mapped(
    owner: &InitialImageControl,
    region: &'static ToolRegion,
) {
    let raw = INSTALLED.load(Ordering::Acquire);
    if raw.is_null() {
        return;
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
        s.control.as_ptr() as usize == owner.control
            && owner.installation.load(Ordering::Acquire) == 3
            && owner.lifecycle.load(Ordering::Acquire) == 2,
    );
    let Frontend::Installed(facts) = p.frontend else {
        die(INVALID)
    };
    check(
        facts.host == owner.installed_host.load(Ordering::Acquire)
            && core::ptr::eq(facts.region, region)
            && owner.region.load(Ordering::Acquire) == core::ptr::from_ref(region).cast_mut(),
    );
    unsafe { tool_init::verify_thread(s, p, false) };
    p.frontend = Frontend::Retired(facts);
    s.busy.store(false, Ordering::Release);
}

// No startup permission is revived here: frame_facts always refuses Retired.
// Called only while the same relay busy exclusion is held and after the actual
// continuation supplied its Running callback host and captured kernel mask.
pub(super) unsafe fn verify_callback_frontend(
    s: &RelayState,
    p: &Progress,
    host: usize,
    callback_mask: u64,
) -> (&'static ToolRegion, FrameFacts) {
    let Frontend::Retired(installed) = p.frontend else {
        die(INVALID)
    };
    check(p.libc_cleaned && p.tool_init && host != 0 && host == installed.host);
    check(super::super::super::control_pointer() == s.control.as_ptr());
    check(
        crate::guest::tool_region::published_owner()
            .is_some_and(|region| core::ptr::eq(region, installed.region)),
    );
    check(
        installed
            .region
            .registered_alternate_stack()
            .is_some_and(|stack| {
                stack.bottom == installed.signal.stack.lo && stack.top == installed.signal.stack.hi
            }),
    );
    check(crate::trap::has_dispatcher() && crate::trap::signal_return_restricted());
    check(crate::guest::signal::reserved_signal_mask() == installed.reserved);
    // This is the authentic mask captured by the pending guest continuation,
    // not the old startup mask. Reserved runtime deliveries must remain open.
    check(callback_mask & installed.reserved == 0);
    let facts = FrameFacts {
        mask: callback_mask,
        ..installed.signal
    };
    unsafe { verify_signal_facts(facts, Some(installed.reserved), true) };
    (installed.region, facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installed_startup_is_never_guest_callback_or_lifecycle_authority() {
        assert!(eligible_phase(2, 0, 1));
        for (phase, ready, state) in [
            (1, 0, 1),
            (2, 1, 1),
            (3, 1, 1),
            (4, 0, 1),
            (4, 1, 1),
            (6, 0, 1),
            (2, 0, 0),
        ] {
            assert!(!eligible_phase(phase, ready, state));
        }
    }
    #[test]
    fn live_stack_onstack_and_saved_frame_flags_are_distinct() {
        assert!(checked_registered_stack(
            0x1000, 0x5000, 0x1000, 0x4000, 0, false
        ));
        assert!(checked_registered_stack(
            0x1000,
            0x5000,
            0x1000,
            0x4000,
            libc::SS_ONSTACK,
            true
        ));
        assert!(!checked_registered_stack(
            0x1000, 0x5000, 0x1000, 0x4000, 0, true
        ));
        assert!(!checked_registered_stack(
            0x1000,
            0x5000,
            0x1000,
            0x4000,
            libc::SS_ONSTACK,
            false
        ));
        for (base, size, flags) in [
            (0x2000, 0x4000, libc::SS_ONSTACK),
            (0x1000, 0x3000, libc::SS_ONSTACK),
            (0x1000, 0x4000, libc::SS_DISABLE),
        ] {
            assert!(!checked_registered_stack(
                0x1000, 0x5000, base, size, flags, true
            ));
        }
        assert!(!checked_registered_stack(
            0x5000, 0x1000, 0x5000, 0x4000, 0, false
        ));
        assert!(!checked_registered_stack(
            0x1000, 0x1000, 0x1000, 0, 0, false
        ));
    }
    #[test]
    fn installed_ordinary_mask_unblocks_only_actual_reserved_signals() {
        let sys = 1_u64 << (libc::SIGSYS - 1);
        let segv = 1_u64 << (libc::SIGSEGV - 1);
        let mask = ordinary_mask(sys | segv);
        assert_eq!(mask & (sys | segv), 0);
        assert_ne!(mask & (1_u64 << (libc::SIGUSR1 - 1)), 0);
        assert_eq!(
            mask & ((1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1))),
            0
        );
        assert_ne!(mask | sys, mask); // current handler mask differs from saved uc_sigmask
    }
}
