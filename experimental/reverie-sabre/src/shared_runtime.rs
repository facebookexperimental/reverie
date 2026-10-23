/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! SaBRe's plugin ABI for the shared in-guest runtime: what a runtime library
//! adds to be loaded by the SaBRe loader as its plugin (SaBRe switch, step
//! 5c, commit R1; dev-hermit `ai_docs/2026-10-17-sabre-switch-design.md`
//! sections 3 and 4).
//!
//! The runtime library invokes [`crate::shared_runtime_plugin!`] with its install
//! body, the same function its preload constructor runs. The loader then:
//!
//! 1. calls `sbr_init`, which registers no function intercept and no vDSO
//!    callback, only `post_load`, an RDTSC handler (below) and a syscall
//!    handler that refuses (the loader calls it only without post-arm
//!    routing, which step 2 rules out);
//! 2. reads `reverie_sabre_post_arm_routing_v1` (1), so from then on it hands
//!    every syscall of a rewritten site to `reverie_sabre_routed_syscall_v1`;
//! 3. calls `post_load`, which runs the install body with the plugin's
//!    [`Settings`] (the launch specification's `NAME=VALUE` settings that the
//!    loader does not consume itself): it publishes the Tool and arms the
//!    shared runtime's seccomp filter, like in-guest-trap's constructor;
//! 4. returns to the client's constructors and `main`.
//!
//! The install body runs in `post_load` rather than `sbr_init` (where design
//! section 3 put it, with `post_load` only arming): the shared installer
//! publishes the Tool and arms the filter in one step, and arming in
//! `sbr_init` would put the loader's remaining start-up work under the filter
//! before routing is on. Hence the guards on calls before arming, below.
//!
//! Before the runtime is armed, a routed syscall on the installer thread is
//! the install body's own (one of its calls that reaches a rewritten site),
//! apart from the accepted bootstrap gap below, and runs natively. Under the raw launch below the process is single-threaded
//! after `execve` and no client initializer has run. The plugin still
//! checks that a pre-arm call comes from the thread running the install
//! body, and refuses one that would create a process or thread or replace
//! the image, which a native call from Rust cannot do safely. Once armed,
//! every routed syscall enters the shared runtime through [`crate::shared_entry::dispatch_rewritten_syscall`],
//! with the runtime's own Tool-mode callback and mapping observer, exactly as a
//! patched LiteInst site does. Unrewritten sites trap to the armed filter, as
//! under in-guest-trap.
//!
//! The plugin requires the raw short-site launch
//! (`REVERIE_SABRE_SHORT_SYSCALL_SITES=raw`), which H1's Hermit launch will
//! select (today's Hermit SaBRe launch does not set it).
//! There the loader refuses a client with a `DT_PREINIT_ARRAY`, so, as under
//! in-guest-trap, only ld.so's own work (relocation, IFUNC resolvers, any
//! `LD_AUDIT` module) runs before the runtime is armed, and no client
//! initializer does. That earlier guest code is an accepted bootstrap gap,
//! as it is for in-guest-trap's preload constructor: it runs unsupervised,
//! and a signal handler it installed and armed would run on the installer
//! thread, where its routed syscalls pass the installer check and run
//! natively. In the other short-site mode the client's preinit
//! functions would run first, unsupervised, and a short site's marker would be
//! refused at its first call; the loader does not yet refuse that launch for
//! this plugin (5c commit R2).
//!
//! The loader rewrites RDTSC and RDTSCP sites too, and calls the RDTSC
//! handler for both. The handler executes `LFENCE; RDTSC` in the plugin's
//! own, unrewritten code, so its value is what an unrewritten guest RDTSC
//! gets under the shared runtime: it faults to the runtime's instruction
//! handler when the Tool subscribes to RDTSC, and reads the counter
//! otherwise. Known gaps until the loader leaves these sites to the runtime's
//! own trap (R2), all because the handler cannot tell which instruction the
//! site held: the Tool sees a rewritten RDTSCP as RDTSC, its `TSC_AUX` is the
//! loader's (0), and the fence, which keeps RDTSCP's ordering, gives a plain
//! RDTSC that ordering too (stronger, never weaker).
//!
//! The runtime library declares a global allocator that owns all of its Rust
//! allocations, as Hermit's runtime declares the fixed Tool allocator: Tool
//! callbacks run inside a guest syscall, possibly inside the guest's own
//! allocator. This plugin ABI does not choose one.
//!
//! `post_load` runs from the client's `.preinit_array`, before any library's
//! own initializer, so libc's environment (`getenv`, `std::env`) is not yet
//! set up there: an install body takes what it needs from its settings (or
//! the kernel's initial environment), never from libc's. The shared
//! installer's own environment use sees that empty environment too: it finds
//! no stats-coordinator variable, and removing the coordinator variable would
//! be undone when libc initializes, so an install body passes `false` for it.
//!
//! `calling_from_plugin`, `enter_plugin`, `exit_plugin` and `is_vdso_ready`
//! remain the existing recursion protector's (`ffi/recursion_protector.c`),
//! which the loader resolves by name.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI64;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::ffi::CStr;
use std::io;

use reverie_inguest::guest::runtime_seam::observe_registered_mapping;
use reverie_inguest::guest::runtime_seam::process_tool_syscall_callback;
use reverie_inguest::guest::support::describe_io_error;
use reverie_sabre_stats::SabreDispatchRoute;

use crate::ffi;
use crate::shared_entry::refuse_with;
use crate::shared_entry::write_stderr;

/// The runtime library's install body: publish the Tool and arm the runtime.
pub type InstallFn = unsafe fn(settings: &Settings) -> io::Result<()>;

/// The plugin's settings: the loader's plugin arguments after the plugin's
/// own path, which the loader keeps for the process's lifetime. Under a
/// launch specification each is `NAME=VALUE`. Reading them does not
/// allocate. The strings are borrowed for the install body's call only: in
/// the command-line launch they are the client's initial argument strings,
/// which the guest may overwrite later, so copy what you keep.
pub struct Settings {
    argv: *const *mut libc::c_char,
    count: usize,
}

impl Settings {
    /// Every setting, in order.
    pub fn iter(&self) -> impl Iterator<Item = &CStr> {
        // SAFETY: the loader's argument vector holds `count` C strings after
        // the plugin's path and keeps them for the process's lifetime; the
        // borrow keeps them from outliving the install body's call.
        (0..self.count).map(move |index| unsafe { CStr::from_ptr(*self.argv.add(index + 1)) })
    }

    /// The value of the first `NAME=VALUE` setting named `name`.
    pub fn get(&self, name: &[u8]) -> Option<&CStr> {
        self.iter().find_map(|setting| {
            let bytes = setting.to_bytes_with_nul();
            let rest = bytes.strip_prefix(name)?.strip_prefix(b"=")?;
            CStr::from_bytes_with_nul(rest).ok()
        })
    }
}

/// The install body `sbr_init` registered, as an address (0 until then).
static INSTALL: AtomicUsize = AtomicUsize::new(0);

/// The loader's plugin argument vector and count, as `sbr_init` received
/// them; the loader keeps them for the process's lifetime.
static PLUGIN_ARGV: AtomicPtr<*mut libc::c_char> = AtomicPtr::new(core::ptr::null_mut());
static PLUGIN_ARGC: AtomicUsize = AtomicUsize::new(0);

/// Set once the install body has returned successfully: from then on every
/// routed syscall is the guest's and goes to the shared runtime.
static ARMED: AtomicBool = AtomicBool::new(false);

/// The thread running the install body (0 until `post_load` starts): the only
/// thread whose routed syscalls may run natively before arming.
static INSTALLER_TID: AtomicI64 = AtomicI64::new(0);

/// Whether the shared runtime is installed and armed in this process.
pub fn armed() -> bool {
    ARMED.load(Ordering::Acquire)
}

/// `sbr_init` for a shared runtime plugin; [`crate::shared_runtime_plugin!`] exports
/// it with the loader's fixed signature.
///
/// # Safety
///
/// Called only by the SaBRe loader, once, with its own out-parameters.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn sbr_init(
    argc: *mut i32,
    argv: *mut *mut *mut libc::c_char,
    _fn_icept_reg: ffi::icept_reg_fn,
    vdso_callback: *mut Option<ffi::handle_vdso_fn>,
    syscall_handler: *mut Option<ffi::handle_syscall_fn>,
    rdtsc_handler: *mut Option<ffi::handle_rdtsc_fn>,
    post_load: *mut Option<ffi::post_load_fn>,
    install: InstallFn,
) {
    // Keep the recursion protector the loader resolves by name linked in.
    core::hint::black_box(ffi::vdso_clock_gettime_stub as *const ());
    INSTALL.store(install as *const () as usize, Ordering::Release);
    // SAFETY: the loader passes valid out-parameters (the caller's contract).
    unsafe {
        PLUGIN_ARGC.store(usize::try_from(*argc).unwrap_or(0), Ordering::Release);
        PLUGIN_ARGV.store(*argv, Ordering::Release);
        // No vDSO callback: the loader has already detoured the vDSO's entry
        // points at load time, and with no callback those detours run the
        // real functions; the install body then overwrites the same entry
        // points with the shared runtime's trapping stubs, as under
        // in-guest-trap.
        *vdso_callback = None;
        *rdtsc_handler = Some(rdtsc);
        // Used only if post-arm routing were off, which this plugin's report
        // rules out; it fails closed rather than run a guest call natively.
        *syscall_handler = Some(unrouted_syscall);
        *post_load = Some(arm);
    }
}

/// The loader's `post_load`: runs the install body, then routes every later
/// rewritten syscall to the shared runtime.
extern "C" fn arm(_is_static: bool) {
    if armed() {
        return;
    }
    let install = INSTALL.load(Ordering::Acquire);
    if install == 0 {
        // SAFETY: refuse writes and exits through the runtime's trusted gate.
        unsafe { refuse(Refusal::NotInitialized) };
    }
    // SAFETY: only `sbr_init` stores this, from an `InstallFn`.
    let install: InstallFn = unsafe { core::mem::transmute::<usize, InstallFn>(install) };
    INSTALLER_TID.store(current_tid(), Ordering::Release);
    // The first argument is the plugin's own path; the settings follow it.
    let settings = Settings {
        argv: PLUGIN_ARGV.load(Ordering::Acquire),
        count: PLUGIN_ARGC.load(Ordering::Acquire).saturating_sub(1),
    };
    // SAFETY: the loader calls post_load once, on the initial thread, before
    // the client's constructors: the install body's own precondition.
    if let Err(error) = unsafe { install(&settings) } {
        // SAFETY: as above.
        unsafe { refuse(Refusal::InstallFailed(error)) };
    }
    ARMED.store(true, Ordering::Release);
}

/// `reverie_sabre_routed_syscall_v1` for a shared runtime plugin.
///
/// # Safety
///
/// Called only by the SaBRe loader's router: `wrapper_sp` is the frame it
/// passes for the route it reports, and the arguments are the call's.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn routed_syscall(
    route: i64,
    number: i64,
    arg1: i64,
    arg2: i64,
    arg3: i64,
    arg4: i64,
    arg5: i64,
    arg6: i64,
    wrapper_sp: *mut libc::c_void,
) -> i64 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6].map(|arg| arg as u64);
    if !armed() {
        // SAFETY: refuse writes and exits through the runtime's trusted gate;
        // the call itself is the install body's (checked first).
        return unsafe { run_installer_syscall(number, args) };
    }
    let Some(route) = SabreDispatchRoute::from_raw(route) else {
        // SAFETY: refuse writes and exits through the runtime's trusted gate.
        unsafe { refuse(Refusal::UnknownRoute) };
    };
    // SAFETY: armed, so the runtime is installed and its filter armed; the
    // loader's frame for this route and the runtime's own callbacks meet
    // dispatch_rewritten_syscall's contract, which refuses any route but a
    // genuine trampoline before reading the frame.
    unsafe {
        crate::shared_entry::dispatch_rewritten_syscall(
            route,
            wrapper_sp.cast(),
            number,
            args,
            process_tool_syscall_callback,
            observe_registered_mapping,
        )
    }
}

/// Runs a routed syscall before arming natively, if it is the install body's
/// and safe to issue from Rust; refuses it otherwise.
///
/// # Safety
///
/// The runtime is not armed, so the install body is running or the loader
/// misused the plugin; the arguments are the call's.
unsafe fn run_installer_syscall(number: i64, args: [u64; 6]) -> i64 {
    if !is_installer() {
        // SAFETY: refuse writes and exits through the runtime's trusted gate.
        unsafe { refuse(Refusal::NotArmed) };
    }
    match number {
        // A new thread would resume in this Rust frame on another stack
        // (clone, clone3), vfork's child on the parent's, and fork's child
        // would finish the install body as a second, unsupervised installer;
        // a new image would replace the half-installed runtime. The install
        // body needs none of them.
        libc::SYS_clone
        | libc::SYS_clone3
        | libc::SYS_fork
        | libc::SYS_vfork
        | libc::SYS_execve
        | libc::SYS_execveat => {
            // SAFETY: as above.
            unsafe { refuse(Refusal::InstallerProcessCall) }
        }
        // SAFETY: a call on the installer thread, which is the install
        // body's own apart from the module documentation's accepted
        // bootstrap gap; none of the above.
        _ => unsafe { reverie_inguest::trap::raw_syscall6(number, args) },
    }
}

/// Whether this is the thread running the install body.
fn is_installer() -> bool {
    let installer = INSTALLER_TID.load(Ordering::Acquire);
    installer != 0 && current_tid() == installer
}

/// The loader's handler for rewritten RDTSC and RDTSCP sites; see the module
/// documentation.
extern "C" fn rdtsc() -> u64 {
    if !armed() && !is_installer() {
        // SAFETY: refuse writes and exits through the runtime's trusted gate.
        unsafe { refuse(Refusal::RdtscNotArmed) };
    }
    // SAFETY: LFENCE and RDTSC have no preconditions. This site is the
    // plugin's own and never rewritten; once armed, the runtime's
    // instruction handler takes its fault when the Tool subscribes to RDTSC.
    unsafe {
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    }
}

/// This thread's kernel id, through the runtime's trusted gate.
fn current_tid() -> i64 {
    // SAFETY: gettid has no arguments and cannot fail.
    unsafe { reverie_inguest::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) }
}

extern "C" fn unrouted_syscall(
    _syscall: isize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    _arg6: usize,
    _wrapper_sp: *mut ffi::syscall_stackframe,
) -> usize {
    // SAFETY: refuse writes and exits through the runtime's trusted gate.
    unsafe { refuse(Refusal::Unrouted) }
}

enum Refusal {
    NotInitialized,
    InstallFailed(io::Error),
    UnknownRoute,
    Unrouted,
    NotArmed,
    RdtscNotArmed,
    InstallerProcessCall,
}

/// Ends the guest with a named refusal (exit 122), written through the
/// runtime's trusted syscall gate.
unsafe fn refuse(refusal: Refusal) -> ! {
    let message: &[u8] = match refusal {
        Refusal::NotInitialized => {
            b"reverie-sabre: refused: the loader called the shared runtime plugin's post_load before its sbr_init\n"
        }
        Refusal::InstallFailed(error) => {
            // The description allocates from the runtime library's own
            // allocator (the module documentation's contract), never libc's.
            let description = describe_io_error(&error);
            // SAFETY: as below.
            unsafe {
                write_stderr(
                    b"reverie-sabre: refused: the shared runtime failed to install as the SaBRe plugin: ",
                );
                write_stderr(description.as_bytes());
                write_stderr(b"\n");
            }
            // SAFETY: ending the process is always allowed here.
            unsafe { reverie_inguest::guest::support::exit_now(122) }
        }
        Refusal::UnknownRoute => {
            b"reverie-sabre: refused: the SaBRe loader reported a syscall route the shared runtime does not know\n"
        }
        Refusal::Unrouted => {
            b"reverie-sabre: refused: the SaBRe loader called the shared runtime plugin's syscall handler without post-arm routing\n"
        }
        Refusal::NotArmed => {
            b"reverie-sabre: refused: a rewritten syscall reached the shared runtime plugin before it was armed, outside its install body\n"
        }
        Refusal::RdtscNotArmed => {
            b"reverie-sabre: refused: a rewritten RDTSC reached the shared runtime plugin before it was armed, outside its install body\n"
        }
        Refusal::InstallerProcessCall => {
            b"reverie-sabre: refused: the shared runtime's install body created a thread or process or replaced the image before arming\n"
        }
    };
    // SAFETY: the message is a static buffer.
    unsafe { refuse_with(message) }
}

/// Exports SaBRe's plugin ABI from a shared in-guest runtime library whose
/// install body is `$install` (an [`InstallFn`]).
///
/// The exported `sbr_init`, `reverie_sabre_post_arm_routing_v1` (which
/// reports 1) and `reverie_sabre_routed_syscall_v1` are what the SaBRe loader
/// looks up; see the module documentation for the sequence.
#[macro_export]
macro_rules! shared_runtime_plugin {
    ($install:path) => {
        /// SaBRe's fixed plugin initialization ABI.
        ///
        /// # Safety
        ///
        /// Called only by the SaBRe loader.
        #[unsafe(no_mangle)]
        #[allow(clippy::too_many_arguments)]
        pub unsafe extern "C" fn sbr_init(
            argc: *mut i32,
            argv: *mut *mut *mut ::core::ffi::c_char,
            fn_icept_reg: $crate::ffi::icept_reg_fn,
            vdso_callback: *mut ::core::option::Option<$crate::ffi::handle_vdso_fn>,
            syscall_handler: *mut ::core::option::Option<$crate::ffi::handle_syscall_fn>,
            rdtsc_handler: *mut ::core::option::Option<$crate::ffi::handle_rdtsc_fn>,
            post_load: *mut ::core::option::Option<$crate::ffi::post_load_fn>,
            _sabre_path: *const ::core::ffi::c_char,
            _client_path: *const ::core::ffi::c_char,
        ) {
            // SAFETY: forwarded from the loader's call.
            unsafe {
                $crate::shared_runtime::sbr_init(
                    argc,
                    argv,
                    fn_icept_reg,
                    vdso_callback,
                    syscall_handler,
                    rdtsc_handler,
                    post_load,
                    $install,
                )
            }
        }

        /// This plugin arms its own trap path for every unrewritten syscall.
        #[unsafe(no_mangle)]
        pub extern "C" fn reverie_sabre_post_arm_routing_v1() -> i32 {
            1
        }

        /// The loader's router target under post-arm routing.
        ///
        /// # Safety
        ///
        /// Called only by the SaBRe loader's router.
        #[unsafe(no_mangle)]
        #[allow(clippy::too_many_arguments)]
        pub unsafe extern "C" fn reverie_sabre_routed_syscall_v1(
            route: i64,
            number: i64,
            arg1: i64,
            arg2: i64,
            arg3: i64,
            arg4: i64,
            arg5: i64,
            arg6: i64,
            wrapper_sp: *mut ::core::ffi::c_void,
        ) -> i64 {
            // SAFETY: forwarded from the loader's router.
            unsafe {
                $crate::shared_runtime::routed_syscall(
                    route, number, arg1, arg2, arg3, arg4, arg5, arg6, wrapper_sp,
                )
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `body` in a forked child and returns its exit status. The child
    /// runs only atomics and raw syscalls, so forking the test harness is safe.
    fn exit_status_of(body: impl FnOnce()) -> i32 {
        // SAFETY: see above; the child never returns into the harness.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            body();
            // SAFETY: ends the child without running the harness's code.
            unsafe { libc::_exit(0) }
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "{status:#x}");
        libc::WEXITSTATUS(status)
    }

    fn routed(number: i64) -> i64 {
        // SAFETY: the calls below take no pointer arguments, and the frame
        // is not read before arming.
        unsafe { routed_syscall(0, number, 0, 0, 0, 0, 0, 0, core::ptr::null_mut()) }
    }

    #[test]
    fn before_arming_the_installers_routed_syscall_runs_natively() {
        assert!(!armed());
        let status = exit_status_of(|| {
            INSTALLER_TID.store(current_tid(), Ordering::Release);
            let pid = routed(libc::SYS_getpid);
            // SAFETY: the child's own pid.
            let expected = i64::from(unsafe { libc::getpid() });
            // SAFETY: as in exit_status_of.
            unsafe { libc::_exit(if pid == expected { 0 } else { 1 }) }
        });
        assert_eq!(status, 0);
    }

    #[test]
    fn before_arming_another_threads_routed_syscall_is_refused() {
        let status = exit_status_of(|| {
            INSTALLER_TID.store(current_tid() + 1, Ordering::Release);
            routed(libc::SYS_getpid);
        });
        assert_eq!(status, 122);
        // No install body has started at all.
        assert_eq!(
            exit_status_of(|| {
                routed(libc::SYS_getpid);
            }),
            122
        );
    }

    #[test]
    fn before_arming_the_installer_cannot_create_a_process() {
        for number in [
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_execve,
            libc::SYS_execveat,
        ] {
            let status = exit_status_of(|| {
                INSTALLER_TID.store(current_tid(), Ordering::Release);
                routed(number);
            });
            assert_eq!(status, 122, "syscall {number}");
        }
    }

    #[test]
    fn before_arming_only_the_installer_may_read_the_counter() {
        let status = exit_status_of(|| {
            INSTALLER_TID.store(current_tid(), Ordering::Release);
            rdtsc();
        });
        assert_eq!(status, 0);
        let status = exit_status_of(|| {
            INSTALLER_TID.store(current_tid() + 1, Ordering::Release);
            rdtsc();
        });
        assert_eq!(status, 122);
    }
}
