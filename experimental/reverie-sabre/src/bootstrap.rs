/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Optional loader-to-tool bootstrap state transfer.
//!
//! The supervisor owns the meaning of the opaque state. A consumer must bind
//! its schema, config, owner and image generation before applying it to its
//! normally initialized thread. This interface neither creates ThreadState nor
//! sends an RPC, so it cannot mark coordinator RPC readiness.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use syscalls::Errno;

/// Maximum opaque handoff; this is also fixed in the loader protocol.
pub const MAX_STATE_BYTES: usize = 4096;

/// Launch-side private loader opt-in. Its original string bytes are scrubbed
/// and its pointer removed before plugin initialization. Consumers therefore
/// cannot negotiate with `getenv`; [`take_state`] reports the installed
/// callback's presence (`None` means no negotiation) or an explicit error.
pub const ENVIRONMENT: &str = "REVERIE_SABRE_BOOTSTRAP_V1";
/// Invalid ordinary `prctl` option used by the authenticated loader site.
pub const PRCTL_OPTION: u64 = 0x5342_5242;
/// Version passed by IMAGE and TAKE_STATE requests.
pub const VERSION: u64 = 1;
/// ELF symbol on the request's actual syscall instruction, not its wrapper.
pub const SYSCALL_SYMBOL: &str = "sbr_bootstrap_syscall_v1";
/// Bind the real final initial-image stack before entering its dynamic linker.
pub const IMAGE: u64 = 1;
/// Service one original early guest getrandom request.
pub const GETRANDOM: u64 = 2;
/// Take the opaque state once into the initialized consumer.
pub const TAKE_STATE: u64 = 3;

/// Loader-owned callback. It writes at most `capacity` bytes and returns their
/// count, or a negative Linux errno. It consumes the handoff only on success.
pub type TakeStateFn = unsafe extern "C" fn(*mut u8, usize) -> libc::c_long;

static CALLBACK: AtomicUsize = AtomicUsize::new(0);

/// Installs the optional callback before tool construction.
///
/// # Safety
/// The callback must belong to the loaded, lifetime-stable SaBRe loader and
/// obey `TakeStateFn`'s memory contract. This is called only by the loader's
/// optional symbol negotiation, never from an environment-supplied address.
#[doc(hidden)]
pub unsafe fn install(callback: TakeStateFn) -> Result<(), Errno> {
    CALLBACK
        .compare_exchange(0, callback as usize, Ordering::Release, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|_| Errno::EPROTO)
}

/// Takes the supervisor's opaque state once, without issuing a normal RPC.
/// `None` means this loader did not negotiate bootstrap; a refused transfer is
/// an error and must not be converted to a newly seeded thread.
pub fn take_state(destination: &mut [u8]) -> Result<Option<usize>, Errno> {
    let callback = CALLBACK.load(Ordering::Acquire);
    if callback == 0 {
        return Ok(None);
    }
    // SAFETY: install accepts only the lifetime-stable loader callback.
    let callback: TakeStateFn = unsafe { std::mem::transmute(callback) };
    take_with(callback, destination).map(Some)
}

fn take_with(callback: TakeStateFn, destination: &mut [u8]) -> Result<usize, Errno> {
    if destination.is_empty() || destination.len() > MAX_STATE_BYTES {
        return Err(Errno::EINVAL);
    }
    // SAFETY: the slice is writable for its exact capacity, and the installed
    // loader callback promises not to exceed it.
    let result = unsafe { callback(destination.as_mut_ptr(), destination.len()) };
    let count = Errno::from_ret(result as usize)?;
    if count == 0 || count > destination.len() {
        return Err(Errno::EPROTO);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn refused(_: *mut u8, _: usize) -> libc::c_long {
        -(Errno::ESTALE.into_raw() as libc::c_long)
    }

    unsafe extern "C" fn too_long(_: *mut u8, capacity: usize) -> libc::c_long {
        capacity as libc::c_long + 1
    }

    unsafe extern "C" fn empty(_: *mut u8, _: usize) -> libc::c_long {
        0
    }

    #[test]
    fn refused_or_invalid_handoff_cannot_become_an_empty_fresh_state() {
        let mut bytes = [0xa5; 32];
        assert_eq!(take_with(refused, &mut bytes), Err(Errno::ESTALE));
        assert_eq!(take_with(too_long, &mut bytes), Err(Errno::EPROTO));
        assert_eq!(take_with(empty, &mut bytes), Err(Errno::EPROTO));
        assert_eq!(bytes, [0xa5; 32]);
        assert_eq!(take_with(refused, &mut []), Err(Errno::EINVAL));
        assert_eq!(
            take_with(refused, &mut [0xa5; MAX_STATE_BYTES + 1]),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn optional_callback_is_absent_until_installed_and_cannot_be_replaced() {
        let mut bytes = [0xa5; 32];
        assert_eq!(take_state(&mut bytes), Ok(None));
        // SAFETY: both test callbacks are lifetime-stable and obey the
        // callback's bounded-write contract (neither writes any bytes).
        unsafe {
            assert_eq!(install(refused), Ok(()));
            assert_eq!(install(empty), Err(Errno::EPROTO));
        }
        assert_eq!(take_state(&mut bytes), Err(Errno::ESTALE));
        assert_eq!(bytes, [0xa5; 32]);
    }
}
