/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::mem::transmute;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::fence;
use core::sync::atomic::Ordering::*;

use atomic::Atomic;
use lazy_static::lazy_static;

use crate::callbacks;
use crate::signal;
use crate::slot_map::SlotKey;
use crate::slot_map::SlotMap;
use crate::tool::Tool;
use crate::tool::ToolGlobal;

pub mod guard;

pub type HandlerInput = libc::siginfo_t;

/// We need to keep track of the sigaction that the user specified or what was
/// originally provided as a default separately from what we execute directly as
/// a signal handler.
#[derive(Debug, Clone, Copy)]
struct SigActionPair {
    /// Prisinte sigaction provided by the user or os
    guest_facing_action: libc::sigaction,

    /// The actual sigaction we are using
    internal_action: libc::sigaction,
}

impl SigActionPair {
    /// Create a new SigActionPair from the original sig action and an override
    /// for the default handler. The created pair will contain the original
    /// action, and a synthetic action with the handler replaced if an override
    /// is provided or if the the sa_sigaction is one of the non-function-
    /// pointer values (`SI_DFL`, `SI_ERR`, `SI_IGN`)
    fn new(original: libc::sigaction, override_handler: Option<libc::sighandler_t>) -> Self {
        let mut internal_action = original.clone();

        // This is safe because it is only reading from a mut static that is
        // guaranteed to have been completely set before this function
        // is called
        internal_action.sa_sigaction = unsafe {
            match (original.sa_sigaction, override_handler) {
                (_, Some(override_handler)) => override_handler,
                (libc::SIG_DFL, _) => DEFAULT_EXIT_HANDLER
                    .expect("Default handlers should be set before registering actions"),
                (libc::SIG_IGN, _) => DEFAULT_IGNORE_HANDLER
                    .expect("Default handlers should be set before registering actions"),
                (libc::SIG_ERR, _) => DEFAULT_ERROR_HANDLER
                    .expect("Default handlers should be set before registering actions"),
                (default_action, None) => default_action,
            }
        };

        SigActionPair {
            guest_facing_action: original,
            internal_action,
        }
    }
}

lazy_static! {
    /// This is where we are storing the registered actions for each signal.
    /// We have to store them as Options for now because our slot map requires
    /// its stored type to implement default
    static ref HANDLER_SLOT_MAP: SlotMap<Option<SigActionPair>> = SlotMap::new();
}

// The sighandler_t type has some values that aren't pointers that are still
// valid. They aren't executable, so we need an executable version that we
// control for each. Those  are below

/// Storage of our default handler for the libc::SIG_DFL
static mut DEFAULT_EXIT_HANDLER: Option<libc::sighandler_t> = None;

/// Storage of our default handler for the libc::SIG_IGN
static mut DEFAULT_IGNORE_HANDLER: Option<libc::sighandler_t> = None;

/// Storage of our default handler for the libc::SIG_ERR
static mut DEFAULT_ERROR_HANDLER: Option<libc::sighandler_t> = None;

/// This function invokes the function specified by the given sigaction directly
/// with the given signal value or siginfo as arguments depending on whether
/// the sigaction's flags indicate it is expecting a sigaction or siginfo.
/// Note. In the case that the action is requesting sigaction, the 3rd argument
/// to the handler will always be null. The specifications for sigaction say the
/// third argument is a pointer to the context for the signal being raised, but
/// we cannot guarantee that context will be valid with the handler function is
/// executed. It also seems like that argument's use is rare, so we are omitting
/// it for the time being. When T122210155, we should be able to provide the ctx
/// argument without introducing unsafety.
unsafe fn invoke_signal_handler(
    signal_val: libc::c_int,
    action: &libc::sigaction,
    sig_info: libc::siginfo_t,
) {
    if action.sa_flags & libc::SA_SIGINFO > 0 {
        let to_run: extern "C" fn(libc::c_int, *const libc::siginfo_t, *const libc::c_void) =
            transmute(action.sa_sigaction as *const libc::c_void);
        to_run(
            signal_val,
            &sig_info as *const libc::siginfo_t,
            ptr::null::<libc::c_void>(),
        );
    } else {
        let to_run: extern "C" fn(libc::c_int) =
            transmute(action.sa_sigaction as *const libc::c_void);
        to_run(signal_val);
    }
}

/// Register the given sigaction as the default. Optionally an override function
/// can be passed in that will us to change the default handler for an action
fn insert_action(
    sigaction: libc::sigaction,
    override_default_handler: Option<libc::sighandler_t>,
) -> SlotKey {
    HANDLER_SLOT_MAP.insert(Some(SigActionPair::new(
        sigaction,
        override_default_handler,
    )))
}

/// Register a signal handler for the guest and return the sigaction currently
/// registered for the specified signal
#[allow(dead_code)]
pub fn register_guest_handler(signal_value: i32, new_action: libc::sigaction) -> libc::sigaction {
    register_guest_handler_impl(signal_value, new_action, false)
        .expect("All signals should have pre-registered guest handlers before now")
}

/// This is our replacement for default handlers where
/// `libc::sighandler_t = libc::SIG_DFL` which is the default handler
/// value for almost all signals. This function will stop all threads in order
/// to raise thread-exit events for each
pub extern "C" fn default_exit_handler<T: ToolGlobal>(
    _signal_value: libc::c_int,
    _siginfo: *const libc::siginfo_t,
    _ctx: *const libc::c_void,
) {
    callbacks::exit_group::<T>(0);
}

/// This is our replacement for default handlers where
/// `libc::sighandler_t = libc::SIG_IGN` which is the default handler
/// value for lots of signals. This function does nothing, but allows uniform
/// treatment of function pointers in signal handlers (instead of checking for)
///specific values of sighandler_t before calling
pub extern "C" fn default_ignore_handler<T: ToolGlobal>(
    _signal_value: libc::c_int,
    _siginfo: *const libc::siginfo_t,
    _ctx: *const libc::c_void,
) {
}

/// This is our replacement for default handlers where
/// `libc::sighandler_t = libc::SIG_ERR` which is the default handler
/// value for signals representing unrecoverable errors (SIGILL, SIGSEGV, etc).
/// This function will stop all threads in order to raise thread-exit events
/// for each, but the error code will be non-zero
pub extern "C" fn default_error_handler<T: ToolGlobal>(
    _signal_value: libc::c_int,
    _siginfo: *const libc::siginfo_t,
    _ctx: *const libc::c_void,
) {
    callbacks::exit_group::<T>(1);
}

/// This macro defines the functions and constants and api for signals based on
/// an input set of signal. There should only be one invocation of the macro,
/// and it is below. It allows us to express the list of signals we are
/// supporting with properties on each to deal with edge cases
macro_rules! generate_signal_handlers {
    (
        default_exit_handler: $default_exit_handler_fn:expr,
        default_ignore_handler: $default_ignore_handler_fn:expr,
        default_error_handler: $default_error_handler_fn:expr,
        signals: [$($signal_name:ident $({
        $(override_default = $override_default_handler:expr;)?
        $(guest_handler_allowed = $guest_handler_allowed:expr;)?
    })?),+$(,)?]) => {

        /// All signal values as i32
        mod signal_values {
            $(
                pub const $signal_name: i32 = libc::$signal_name as i32;
            )+
        }

        /// Storage for the slot keys that point to the handlers for each signal
        mod handler_keys {
            use super::*;

            $(
                pub static $signal_name: Atomic<Option<SlotKey>> = Atomic::new(None);
            )+
        }

        /// Handler functions for each signal
        mod reverie_handlers {
            use super::*;

            $(
                #[allow(non_snake_case)]
                pub fn $signal_name(handler_input: HandlerInput) {

                    if let Some(Some(SigActionPair {
                        internal_action,
                        ..
                    })) = handler_keys::$signal_name
                        .load(Relaxed)
                        .and_then(|key| HANDLER_SLOT_MAP.get(key))
                    {

                        unsafe {
                            invoke_signal_handler(
                                signal_values::$signal_name as libc::c_int,
                                internal_action,
                                handler_input,
                            );
                        }
                    }
                }
            )+
        }

        /// This is the function that will be registered for all signals.
        /// guest and default handlers for each signal will be dispatched from
        /// here using the global sequencer to prevent signals from interfering
        /// with reverie or its tool's state
        pub extern "C" fn central_handler<T: ToolGlobal>(
            real_signal_value: i32,
            sig_info_ptr: *const libc::siginfo_t,
            _ctx: *const libc::c_void,
        ) {
            let wrapped_handler = match real_signal_value {
                $(
                    signal_values::$signal_name => reverie_handlers::$signal_name,
                )+
                _ => panic!("Invalid signal {}", real_signal_value)
            };

            let sig_info = unsafe { *sig_info_ptr };
            T::global().handle_signal_event(real_signal_value);
            signal::guard::invoke_guarded(wrapped_handler, sig_info);
        }

        /// This is the funtion that needs to be called to initialize all the
        /// signal handling machinery. This will register our central handler
        /// for all signals
        pub fn register_central_handler<T: ToolGlobal>() {

            // Register the default handler functions that correspond to the
            // scalar sighandler_t behaviors. This is safe because this will
            // only be done before the first syscall is handled, and only
            // one thread will be active.
            unsafe {
                DEFAULT_EXIT_HANDLER = Some($default_exit_handler_fn
                    as *const libc::c_void
                    as libc::sighandler_t);
                DEFAULT_IGNORE_HANDLER = Some($default_ignore_handler_fn
                    as *const libc::c_void
                    as libc::sighandler_t);
                DEFAULT_ERROR_HANDLER = Some($default_error_handler_fn
                    as *const libc::c_void
                    as libc::sighandler_t);
            }

            // To make sure handlers are set before continuing
            fence(SeqCst);

            $( unsafe {

                let sa_sigaction = central_handler::<T>
                    as extern "C" fn(libc::c_int, *const libc::siginfo_t, *const libc::c_void)
                    as *mut libc::c_void
                    as libc::sighandler_t;

                let mut sa_mask = MaybeUninit::<libc::sigset_t>::uninit();
                assert_eq!(0, libc::sigemptyset(sa_mask.as_mut_ptr()), "Failed to create sigset");
                libc::sigaddset(sa_mask.as_mut_ptr(), signal_values::$signal_name);

                let action = libc::sigaction {
                    sa_sigaction,
                    sa_mask: sa_mask.assume_init(),
                    sa_flags: 0x14000000,
                    sa_restorer: None,
                };

                let mut original_action : MaybeUninit<libc::sigaction>
                    = MaybeUninit::uninit();

                assert_eq!(0, libc::sigaction(
                    signal_values::$signal_name as libc::c_int,
                    &action as *const libc::sigaction,
                    original_action.as_mut_ptr(),
                ), "Failed to register central handler for {}", stringify!($signal_name));

                let override_default_handler = None $($(
                    .or(Some(
                        $override_default_handler as *const libc::c_void as libc::sighandler_t)
                    )
                )?)?;

                let handler_key = insert_action(
                    original_action.assume_init(),
                    override_default_handler,
                );

                handler_keys::$signal_name.store(Some(handler_key), SeqCst);
            } )+
        }

        /// Register the given action for the given signal. The force-allow
        /// flag means that the handler will be registered even if guest
        /// handlers are disallowed for the given signal. Return a copy of the
        /// sigaction that was previously associated with the given signal
        fn register_guest_handler_impl(
            signal_value: i32,
            new_action: libc::sigaction,
            force_allow: bool
        ) -> Option<libc::sigaction> {

            let (handler_key, guest_handler_allowed, signal_name) = match signal_value {
                $(
                    signal_values::$signal_name => {
                        let allowed = force_allow || (true $($( && $guest_handler_allowed)?)?);
                        let signal_name = stringify!($signal_name);
                        (&handler_keys::$signal_name, allowed, signal_name)
                    },
                )+
                _ => panic!("Invalid signal {}", signal_value)
            };

            if !guest_handler_allowed {
                panic!("Guest handler registration for {} is not supported", signal_name);
            }

            let new_action_key = insert_action(new_action, None);
            let old_action_key_opt = handler_key.swap(Some(new_action_key), Relaxed);

            // The first time this function is called, there won't be a stored
            // key for every signal action, but if there is return it. It is
            // safe because the key being used must have come from the same
            // map, and because no elements are deleted, the get operation
            // will always succeed
            old_action_key_opt.map(|old_action_key| unsafe {
                HANDLER_SLOT_MAP.get_unchecked(old_action_key).unwrap().guest_facing_action
            })
        }

        /// Get the sigaction registered for the given signal if there is one.
        /// The returned sigaction will either be the original default sigaction
        /// set by default for the application or the unaltered sigaction
        /// registered by the user
        #[allow(dead_code)]
        pub fn get_registered_guest_handler(
            signal_value: i32
        ) -> libc::sigaction {
            let current_action_key = match signal_value {
                $(
                    signal_values::$signal_name => {
                        handler_keys::$signal_name
                            .load(Relaxed)
                            .expect("All signals should have guest handlers before now")
                    }
                )+
                _ => panic!("Invalid signal {}", signal_value)
            };

            // This is safe because the key being used must have come from the
            // same map, and because no elements are deleted, the get operation
            // will always succeed
            unsafe {
                HANDLER_SLOT_MAP.get_unchecked(current_action_key)
                    .unwrap().guest_facing_action
            }
        }
    };
}

generate_signal_handlers! {
    default_exit_handler: default_exit_handler::<T>,
    default_ignore_handler: default_ignore_handler::<T>,
    default_error_handler: default_error_handler::<T>,

    signals: [
        SIGHUP,
        SIGINT,
        SIGQUIT,
        // SIGILL, <- needs special synchronous handling Todo(T129735993)
        SIGTRAP,
        SIGABRT,
        SIGBUS,
        SIGFPE,
        // SIGKILL, <- cannot be handled directly Todo(T129348205)
        SIGUSR1,
        // SIGSEGV, <- needs special synchronous handling Todo(T129735993)
        SIGUSR2,
        SIGPIPE,
        SIGALRM,
        SIGTERM,
        SIGSTKFLT {
            // This is our controlled exit signal. If the guest tries to
            // register a handler for it, we will panic rather than chancining
            // undefined behavior
            override_default = crate::callbacks::handle_exit_signal::<T>;
            guest_handler_allowed = false;
        },
        // SIGCHLD, <- Causing problems in test_rr_syscallbuf_sigstop T128095829
        SIGCONT,
        // SIGSTOP, <- cannot be handled directly Todo(T129348205)
        SIGTSTP,
        SIGTTIN,
        SIGTTOU,
        SIGURG,
        SIGXCPU,
        SIGXFSZ,
        SIGVTALRM,
        SIGPROF,
        SIGWINCH,
        SIGIO,
        SIGPWR,
        SIGSYS,
    ]
}
