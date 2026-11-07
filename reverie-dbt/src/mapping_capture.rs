/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Prepared, non-yielding bridge to the native cooperative capture operation.

use reverie::GlobalTool;
use reverie::MappingCaptureError;
use reverie::NativeMmOwnership;
use reverie::PreparedMappingCapture;
use reverie::Tid;
use reverie::Tool;
use reverie_rpc_transport::RequestEnvelope;
use reverie_rpc_transport::codec::decode_exact_bounded;
use reverie_rpc_transport::codec::encode_bounded;

use crate::NativePrivateMemorySnapshot;

const REQUEST_CAPACITY: usize = 64 * 1024;
const RESPONSE_CAPACITY: usize = 2 * 1024 * 1024 + 64 * 1024;

/// ABI-15 fixed arguments. Payload pointers are supplied by operation zero and
/// refer to prefaulted certified native storage; payloads never live on the
/// client stack. The native operation releases the exact primary lease before
/// restoring the caller's physical mask.
#[repr(C)]
#[derive(Default)]
pub struct NativeMappingCapture {
    /// Entire expected initialized native ownership certificate.
    pub expected: NativePrivateMemorySnapshot,
    /// Controller operation number, never reused within the installed run.
    pub nonce: u64,
    /// Controller-authenticated physical launch-root identity.
    pub root_pid: i32,
    /// Borrowed existing reserved primary descriptor.
    pub fd: i32,
    /// Native-owned request storage.
    pub request: *mut u8,
    /// Capacity supplied by the native producer.
    pub request_capacity: usize,
    /// Complete encoded request length (without the frame prefix).
    pub request_length: usize,
    /// Native-owned response storage.
    pub response: *mut u8,
    /// Capacity supplied by the native producer.
    pub response_capacity: usize,
    /// Complete returned frame length, zero on failure.
    pub response_length: usize,
    /// Opaque backend-owned primary lease, never a Tool callback context.
    pub lease: usize,
    /// Fixed unlock-only backend hook, called exactly once after restoration of
    /// the helper and before restoration of the caller mask.
    pub release_lease: Option<unsafe extern "C" fn(usize, i32)>,
}

const _: () = {
    assert!(std::mem::size_of::<NativeMappingCapture>() == 256);
    assert!(std::mem::offset_of!(NativeMappingCapture, request) == 192);
    assert!(std::mem::offset_of!(NativeMappingCapture, release_lease) == 248);
};

/// Operation zero lends fixed native storage; operation one performs the
/// complete cooperative transaction after operation two independently
/// authenticates the Pending token on the existing backend control connection.
/// Operation one returns success only after safe restoration.
pub type MappingCapture = unsafe extern "C" fn(usize, u32, *mut NativeMappingCapture) -> i32;

static CAPTURE: std::sync::OnceLock<MappingCapture> = std::sync::OnceLock::new();

/// Install the ABI-15 native primitive before application callbacks begin.
pub fn install_mapping_capture(capture: MappingCapture) {
    let _ = CAPTURE.set(capture);
}

pub(crate) fn execute<T: Tool>(
    context: usize,
    tid: Tid,
    config: &<T::GlobalState as GlobalTool>::Config,
    prepared: PreparedMappingCapture<<T::GlobalState as GlobalTool>::Request>,
) -> Result<<T::GlobalState as GlobalTool>::Response, MappingCaptureError> {
    if T::native_mm_ownership(config) != NativeMmOwnership::ManagedRuntimeOnly {
        return Err(MappingCaptureError::Unavailable);
    }
    let capture = CAPTURE.get().ok_or(MappingCaptureError::Unavailable)?;
    let (token, private, request) = prepared.into_parts();
    if private.regions.is_empty() || private.regions.len() > 8 {
        return Err(MappingCaptureError::Identity);
    }
    // Tool serialization occurs before any borrow, mask or helper request.
    let encoded = encode_bounded::<_, REQUEST_CAPACITY>(&RequestEnvelope { from: tid, request })
        .map_err(|_| MappingCaptureError::Frame)?;
    let mut args = NativeMappingCapture {
        expected: NativePrivateMemorySnapshot {
            owner: private.owner,
            version: private.version,
            state: 1,
            count: private.regions.len() as u32,
            ..Default::default()
        },
        nonce: token.nonce,
        root_pid: token.identity.process,
        ..Default::default()
    };
    for (range, region) in args.expected.ranges.iter_mut().zip(private.regions) {
        *range = [region.start, region.end];
    }
    // SAFETY: the trusted native ABI writes only this live fixed record.
    if unsafe { capture(context, 0, &mut args) } != 1 {
        return Err(MappingCaptureError::Unavailable);
    }
    if args.request.is_null()
        || args.response.is_null()
        || args.request_capacity != REQUEST_CAPACITY
        || args.response_capacity != RESPONSE_CAPACITY
    {
        return Err(MappingCaptureError::Frame);
    }
    // SAFETY: native operation zero lends REQUEST_CAPACITY initialized bytes
    // from this image's private slot; encode_bounded has already bounded input.
    let authorization = reverie_rpc_transport::mapping_capture::encode_request(token)
        .map_err(|_| MappingCaptureError::Frame)?;
    // Native preflight uses the same fixed buffers before any executor parks.
    // Keep the complete Tool request outside Closed until this ACK succeeds.
    let mut lease = crate::sync_rpc::borrow_mapping_capture_primary()?;
    args.fd = lease.fd();
    args.lease = (&mut lease as *mut crate::sync_rpc::MappingCapturePrimary) as usize;
    args.release_lease = Some(crate::sync_rpc::release_mapping_capture_primary);
    unsafe {
        std::ptr::copy_nonoverlapping(authorization.as_ptr(), args.request, authorization.len())
    };
    args.request_length = authorization.len();
    let authorized = unsafe { capture(context, 2, &mut args) };
    drop(authorization);
    if authorized != 1 {
        // A failed/partial preflight cannot be reused as ordinary RPC framing.
        unsafe { crate::sync_rpc::release_mapping_capture_primary(args.lease, 0) };
        return Err(MappingCaptureError::Authorization);
    }
    unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), args.request, encoded.len()) };
    args.request_length = encoded.len();
    drop(encoded);
    // No Rust code or decoding runs until the native restoration epilogue.
    let result = unsafe { capture(context, 1, &mut args) };
    let released = lease.is_released();
    drop(lease); // Early pre-mask refusal still releases this ordinary borrow.
    match result {
        1 if released => {}
        0 => return Err(MappingCaptureError::Unavailable),
        -2 => return Err(MappingCaptureError::Timeout),
        -3 => return Err(MappingCaptureError::Transport),
        _ => return Err(MappingCaptureError::Identity),
    }
    if args.response_length > RESPONSE_CAPACITY {
        return Err(MappingCaptureError::Frame);
    }
    // SAFETY: successful operation one supplies a complete bounded frame and
    // restored both executors. No reentrant capture occurs before this decode.
    let bytes = unsafe { std::slice::from_raw_parts(args.response, args.response_length) };
    decode_exact_bounded::<_, RESPONSE_CAPACITY>(bytes).map_err(|_| MappingCaptureError::Frame)
}

#[cfg(test)]
mod tests;
