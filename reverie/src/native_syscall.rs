/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

//! Synchronous observations of a particular native syscall attempt.
//!
//! These objects are local capabilities, never serialized requests or stream
//! events. Attempt identities correlate observations only: their allocation or
//! decoder order must not determine guest scheduling or policy.

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

use crate::Errno;
use crate::Error;
use crate::reserved_input::InputDescriptorFacts;
use crate::reserved_input::InputGrantKind;
use crate::reserved_input::InputNativeError;
use crate::reserved_input::InputTaskId;
use crate::reserved_input::InputTaskRegistration;
use crate::reserved_input::InputUnavailable;
use crate::reserved_input::PhysicalInjectionId;
use crate::reserved_input::ReservedInputControl;
use crate::reserved_input::ReservedInputImage;

/// Opaque mechanical correlation identity, not a guest identifier or clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NativeSyscallId(u64);
impl NativeSyscallId {
    /// Backend constructor, using a separately allocated run-local namespace.
    pub fn from_backend_counter(value: u64) -> Self {
        Self(value)
    }
}

/// Who owns the effect of the issued call, not who happened to invoke a helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSyscallPurpose {
    /// An application effect, including helper-created guest-visible objects.
    Application,
    /// An authenticated backend-private setup or repair effect.
    BackendPrivate,
}

/// ABI evidence for the actual instruction, never inferred only from a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSyscallAbi {
    /// Linux audit architecture from an authenticated entry or a verified
    /// backend-owned native instruction and execution mode. x32 retains its
    /// distinguishing bit in the raw syscall number.
    Linux {
        /// Unmodified Linux audit architecture identifier.
        audit_arch: u32,
    },
    /// The backend could not authenticate this instruction's ABI. Consumers
    /// must not decode its number as their build target's native ABI.
    Unverified,
}

/// Immutable request at the final owned native stop.
#[derive(Debug, Clone)]
pub struct NativeSyscallCall {
    /// Correlation only; it conveys no ordering or execution grant.
    pub id: NativeSyscallId,
    /// ABI provenance for these raw operands.
    pub abi: NativeSyscallAbi,
    /// Raw ABI number, retaining unknown syscall numbers.
    pub number: u64,
    /// All six actual operands about to be issued.
    pub args: [u64; 6],
    /// Explicit origin of the native effect.
    pub purpose: NativeSyscallPurpose,
    /// An explicit caller operation accompanies this exact physical request.
    /// This is association only, not proof of grant, access or FD membership.
    pub operation_bound: bool,
    /// Matching call-local input receipt, when present.
    pub input_receipt: Option<PhysicalInjectionId>,
    /// Complete immutable future input. Ordinary memory still contains the old
    /// image during the observation; consumers must not confuse the two.
    pub staged_image: Option<ReservedInputImage>,
}

/// One leaf-lock snapshot. None of these observations grants execution.
#[derive(Debug, Clone)]
pub struct NativeSyscallAuthority {
    /// Exact native image/task incarnation.
    pub registration: InputTaskRegistration,
    /// Published logical grant, if any, and its kind.
    pub grant: Option<(u64, InputGrantKind)>,
    /// Backend-proved private file-table lifetime, not a kernel fdget receipt.
    pub files_proven_unshared: bool,
}

/// Copied census facts. The provider retains every native pin until it drops.
#[derive(Debug, Clone)]
pub struct NativeDescriptorSnapshot {
    /// Complete census, or an explicit error rather than an empty table.
    pub descriptors: Vec<InputDescriptorFacts>,
    /// Target mount table with each descriptor's authenticated path context.
    pub mountinfo: Result<Vec<u8>, InputNativeError>,
}

/// Restricted, synchronous facts borrowed from the actual native stop.
///
/// No injection, guest memory access, register changes, resume, RPC or await is
/// exposed. Object pins belong to the provider and are dropped before resume.
/// A snapshot is not proof of a later numeric descriptor lookup.
pub trait NativeSyscallFacts {
    /// Retained run-local control, when installed.
    fn control(&self) -> Option<ReservedInputControl>;
    /// Exact stopped task/image, when the backend has that registry.
    fn task(&self) -> Option<InputTaskId>;
    /// Registration, grant and table proof captured together.
    fn authority(&self) -> Result<NativeSyscallAuthority, InputUnavailable>;
    /// Pin and inspect one actual native descriptor.
    fn descriptor(&self, fd: i32) -> Result<InputDescriptorFacts, InputUnavailable>;
    /// Pin and inspect the complete native descriptor table.
    fn descriptors(&self) -> Result<NativeDescriptorSnapshot, InputUnavailable>;
}

/// What was actually established about a particular physical attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSyscallEvent {
    /// A native transition was successfully issued. This is not success of the
    /// syscall, nor proof that its body has executed.
    ResumeIssued,
    /// The decoder independently proved that the native body did not execute.
    /// This may follow ResumeIssued when interrupted before the instruction.
    ProvedNotRun,
    /// An actual native result. Errno does not imply absence of side effects.
    NativeResult(Result<i64, Errno>),
    /// An issued attempt lost its result proof (including a tail with no exit
    /// stop). This is uncertainty, not a fabricated result or installation.
    ResultUnobserved,
    /// An authenticated later boundary proves this attempt's native effects
    /// ended, without recovering its result or descriptor membership. This is
    /// distinct from merely dropping a callback or observing PTRACE_EVENT_EXIT.
    EffectsComplete,
}

/// Exact per-physical observation owner retained by the backend on cancellation.
/// Completing this receipt does not retire a caller's copyout/readmission lease.
pub trait NativeSyscallObserver: Debug + Send + Sync {
    /// Observe a transition. Result-stop facts are supplied only while that
    /// original stop is owned; native results precede restoration/Tool reentry.
    fn observe(
        &self,
        call: &NativeSyscallCall,
        event: NativeSyscallEvent,
        facts: Option<&dyn NativeSyscallFacts>,
    ) -> Result<(), Error>;
}

/// Explicit operation owner supplied by the caller before it releases control.
/// Its cookies must refer to this operation, never a task-global next/last call.
pub trait NativeOperationObserver: Debug + Send + Sync + std::any::Any {
    /// Called at the final native stop, before any staged image is filled.
    fn observe(
        &self,
        facts: &dyn NativeSyscallFacts,
        call: &NativeSyscallCall,
    ) -> Result<Option<Arc<dyn NativeSyscallObserver>>, Error>;
}

/// Cloneable ownership binding passed explicitly through one Guest wrapper.
#[derive(Debug, Clone)]
pub struct NativeOperation {
    state: Arc<NativeOperationState>,
    request: Option<Arc<NativeRequestBinding>>,
}

/// Immutable physical request captured while its caller still owns its grant.
/// This is a description, not authority to issue or to reinterpret another ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeSyscallRequest {
    /// Authenticated intended ABI, or explicit uncertainty requiring coverage.
    pub abi: NativeSyscallAbi,
    /// Exact intended syscall number.
    pub number: u64,
    /// Exact intended operands, including any already-translated buffers.
    pub args: [u64; 6],
}

trait RequestProof: Debug + Send + Sync + std::any::Any {}
impl<T: Debug + Send + Sync + std::any::Any> RequestProof for T {}
#[derive(Debug)]
struct NativeRequestBinding {
    request: NativeSyscallRequest,
    proof: Arc<dyn RequestProof>,
}
#[derive(Debug)]
struct NativeOperationState {
    observer: Arc<dyn NativeOperationObserver>,
    calls: Arc<Mutex<NativeOperationCalls>>,
}
#[derive(Debug, Default)]
struct NativeOperationCalls {
    closed: bool,
    attempts: Vec<Arc<AtomicU8>>,
}

/// Mechanical completion proof with no observer, Tool or control backreference.
#[derive(Debug, Clone)]
pub struct NativeOperationCompletion(Arc<Mutex<NativeOperationCalls>>);
impl NativeOperationCompletion {
    /// Compare opaque operation identity, without exposing allocation order.
    pub fn same_operation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    /// Backend-only closure at authenticated retirement of this operation's
    /// native owner. Ordinary results, future Drop and user continuations are
    /// not such proof. This closes admission of future calls but does not mark
    /// any attempt complete or retire a Tool's logical lease.
    pub fn close_after_native_owner_retired(&self) {
        self.0.lock().unwrap().closed = true;
    }

    /// Closed operation with affirmative completion/no-issue proof for every
    /// registered attempt. This never grants logical lease retirement.
    pub fn effects_complete(&self) -> bool {
        let calls = self.0.lock().unwrap();
        calls.closed
            && calls
                .attempts
                .iter()
                .all(|state| state.load(Ordering::Acquire) == EFFECTS_COMPLETE)
    }
}

const PREPARING: u8 = 0;
const TRANSITION_STARTED: u8 = 1;
const EFFECTS_COMPLETE: u8 = 2;

/// Backend's exact call-local activity token. Its state survives the callback.
/// Methods publish mechanical facts only; they do not retire any Tool lease.
#[derive(Debug, Clone)]
pub struct NativeOperationAttempt(Arc<AtomicU8>);
impl NativeOperationAttempt {
    /// Mark the actual transition as attempted before calling the native
    /// transport. A transport error is not automatically proof of no effect.
    pub fn transition_started(&self) {
        let _ = self.0.compare_exchange(
            PREPARING,
            TRANSITION_STARTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    /// Publish a positively authenticated end or independently proved NotRun.
    pub fn effects_ended(&self) {
        self.0.store(EFFECTS_COMPLETE, Ordering::Release);
    }
    /// Account cancellation only if the backend never attempted a native
    /// transition for this physical call. Issued/uncertain calls stay pending.
    pub fn cancelled_before_transition(&self) {
        let _ = self.0.compare_exchange(
            PREPARING,
            EFFECTS_COMPLETE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}
impl NativeOperation {
    /// Bind an already-created caller operation; this does not grant execution.
    pub fn new(owner: Arc<dyn NativeOperationObserver>) -> Self {
        Self {
            state: Arc::new(NativeOperationState {
                observer: owner,
                calls: Arc::new(Mutex::new(NativeOperationCalls::default())),
            }),
            request: None,
        }
    }
    /// Inspect this exact explicitly bound owner, without a task-global lookup.
    /// The returned reference grants no native execution or settlement authority.
    pub fn owner<T: NativeOperationObserver + 'static>(&self) -> Option<&T> {
        let owner: &dyn std::any::Any = self.state.observer.as_ref();
        owner.downcast_ref::<T>()
    }

    /// End the owning caller's operation against future physical calls. This
    /// does not cancel native work or clear any effects/copyout/readmission
    /// obligation. In particular, calling this from a cancellation guard does
    /// not make [`Self::effects_complete`] true for an issued unresolved call.
    pub fn close(&self) {
        self.state.calls.lock().unwrap().closed = true;
    }

    /// Whether the closed operation has no unresolved native effects. Native
    /// result uncertainty can remain after this is true; the Tool must still
    /// preserve that uncertainty and discharge its own logical obligations.
    pub fn effects_complete(&self) -> bool {
        self.proof().effects_complete()
    }

    /// Retain mechanical completion evidence without retaining this operation's
    /// observer or any of its Tool/control references.
    pub fn completion(&self) -> NativeOperationCompletion {
        NativeOperationCompletion(self.state.calls.clone())
    }

    pub(crate) fn proof(&self) -> NativeOperationCompletion {
        self.completion()
    }

    /// Backend registration before preparation of one physical application
    /// call. No event identity is derived from this vector's order.
    pub fn begin_native_attempt(&self) -> Result<NativeOperationAttempt, Error> {
        let mut calls = self.state.calls.lock().unwrap();
        if calls.closed {
            return Err(Error::from(anyhow::anyhow!(
                "native operation is already closed"
            )));
        }
        let state = Arc::new(AtomicU8::new(PREPARING));
        calls.attempts.push(state.clone());
        Ok(NativeOperationAttempt(state))
    }

    /// Backend invocation at the final stopped boundary.
    pub fn observe(
        &self,
        facts: &dyn NativeSyscallFacts,
        call: &NativeSyscallCall,
    ) -> Result<Option<Arc<dyn NativeSyscallObserver>>, Error> {
        self.state.observer.observe(facts, call)
    }

    /// The exact constrained request, when a backend bound it before release.
    /// An unconstrained operation owner returns None. Cloning a constrained view
    /// preserves its binding; it does not constrain other views of this owner.
    pub fn bound_request(&self) -> Option<NativeSyscallRequest> {
        self.request.as_ref().map(|binding| binding.request)
    }

    /// Backend constructor after authenticating a live stopped grant. The
    /// backend must use a private proof type and validate it before every issue.
    /// An existing binding cannot be replaced, even for the same owner.
    pub fn bind_request_from_backend<T: Debug + Send + Sync + 'static>(
        &self,
        request: NativeSyscallRequest,
        proof: T,
    ) -> Result<Self, Error> {
        if self.request.is_some() || self.state.calls.lock().unwrap().closed {
            return Err(anyhow::anyhow!("native-request-already-bound-or-closed").into());
        }
        Ok(Self {
            state: self.state.clone(),
            request: Some(Arc::new(NativeRequestBinding {
                request,
                proof: Arc::new(proof),
            })),
        })
    }

    /// Backend-only typed proof lookup. An unfamiliar proof must be rejected,
    /// not treated as an unconstrained request or interpreted as guest errno.
    pub fn request_proof<T: Debug + Send + Sync + 'static>(&self) -> Option<&T> {
        let proof: &dyn std::any::Any = self.request.as_ref()?.proof.as_ref();
        proof.downcast_ref::<T>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug)]
    struct Empty;
    impl NativeOperationObserver for Empty {
        fn observe(
            &self,
            _: &dyn NativeSyscallFacts,
            _: &NativeSyscallCall,
        ) -> Result<Option<Arc<dyn NativeSyscallObserver>>, Error> {
            Ok(None)
        }
    }
    #[test]
    fn closed_operation_needs_affirmative_completion_for_each_physical_attempt() {
        let operation = NativeOperation::new(Arc::new(Empty));
        let never_issued = operation.begin_native_attempt().unwrap();
        let issued = operation.begin_native_attempt().unwrap();
        issued.transition_started();
        assert!(!operation.effects_complete());
        operation.close();
        never_issued.cancelled_before_transition();
        assert!(!operation.effects_complete());
        issued.cancelled_before_transition();
        assert!(
            !operation.effects_complete(),
            "dropping an issued future is not an effects proof"
        );
        issued.effects_ended();
        assert!(operation.effects_complete());
        assert!(operation.begin_native_attempt().is_err());
        let helper = NativeOperation::new(Arc::new(Empty));
        helper.close();
        assert!(helper.effects_complete());
        assert!(!operation.completion().same_operation(&helper.completion()));
    }
    #[test]
    fn request_views_share_completion_without_sharing_or_replacing_requests() {
        let operation = NativeOperation::new(Arc::new(Empty));
        let first = NativeSyscallRequest {
            abi: NativeSyscallAbi::Unverified,
            number: 1,
            args: [2; 6],
        };
        let second = NativeSyscallRequest { number: 3, ..first };
        let a = operation.bind_request_from_backend(first, 11u64).unwrap();
        let b = operation.bind_request_from_backend(second, 12u64).unwrap();
        assert!(a.completion().same_operation(&b.completion()));
        assert_ne!(a.bound_request(), b.bound_request());
        assert_eq!(a.clone().bound_request(), Some(first));
        assert_eq!(a.clone().request_proof::<u64>(), Some(&11));
        assert!(a.bind_request_from_backend(second, 12u64).is_err());
        assert!(operation.bound_request().is_none());
        operation.close();
        assert!(operation.bind_request_from_backend(first, 11u64).is_err());
        assert!(a.effects_complete());
        assert!(b.effects_complete());
    }

    #[test]
    fn completion_handle_does_not_retain_the_observer() {
        let owner = Arc::new(Empty);
        let weak = Arc::downgrade(&owner);
        let operation = NativeOperation::new(owner);
        let completion = operation.completion();
        operation.close();
        drop(operation);
        assert!(weak.upgrade().is_none());
        assert!(completion.effects_complete());
    }
}
