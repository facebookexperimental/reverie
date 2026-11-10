// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Retention and retirement for a mapped first-image launch: the frame that
//! holds the actual physical capability of each launch step, and the
//! retirement that confirms each one.
//!
//! An embedder constructs a [`RetainedPhysical`] with a fresh
//! [`CleanupReceipt`] before it spawns, retains the spawn result in it at
//! once, and keeps the frame alive until [`cleanup_all`] has confirmed the
//! child's terminal retirement through that receipt. A frame holds only
//! capabilities spawned with its own receipt
//! ([`RetainedPhysical::retain_spawn`] hands any other back), never overwrites
//! one it holds, and no safe method moves one out of it.

use std::io;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;

use super::ChildOwner;
use super::CleanupReceipt;
use super::InitialExecStop;
use super::LaunchFailure;
use super::physical::CancelledPreparation;
use super::physical::Preparation;
use super::physical::PreparationFailure;
use super::physical::PreparedMapping;

fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

/// Whether two receipts are the same shared receipt, not merely equal ones.
fn same_receipt(a: &CleanupReceipt, b: &CleanupReceipt) -> bool {
    std::rc::Rc::ptr_eq(&a.state, &b.state)
}

/// What [`super::ExecStop::spawn`] returns: the initial stop, or the failed
/// launch retaining any child it created.
pub type SpawnResult<'fd> = std::result::Result<InitialExecStop<'fd>, LaunchFailure<'fd>>;

// H owns no kernel wait mechanism: each slot retains the actual existing R
// capability. Place this value outside ALL block_on/catch_unwind expressions.
pub struct RetainedPhysical<'fd> {
    initial: Option<InitialExecStop<'fd>>,
    mapped: Option<PreparedMapping<'fd>>,
    preparation_failure: Option<Box<PreparationFailure<'fd>>>,
    unconfirmed_initial: Option<Box<ChildOwner<'fd>>>,
    launch_failure: Option<LaunchFailure<'fd>>,
    receipt: CleanupReceipt,
    cancelled: Option<CancelledPreparation>,
}
impl<'fd> RetainedPhysical<'fd> {
    // Construct this BEFORE spawn; store either returned capability immediately.
    pub fn empty(receipt: CleanupReceipt) -> Self {
        Self {
            initial: None,
            mapped: None,
            preparation_failure: None,
            unconfirmed_initial: None,
            launch_failure: None,
            receipt,
            cancelled: None,
        }
    }
    /// Retain a spawn result that was spawned with this frame's receipt.
    ///
    /// A result spawned with any other receipt, or one whose slot is already
    /// occupied, is handed back unretained: retirement confirms each capability
    /// through this frame's receipt, so it may hold no other child, and it never
    /// drops a capability it holds.
    pub fn retain_spawn(
        &mut self,
        result: SpawnResult<'fd>,
    ) -> std::result::Result<(), Box<SpawnResult<'fd>>> {
        match result {
            Ok(initial)
                if self.initial.is_none()
                    && same_receipt(&initial.owner.receipt, &self.receipt) =>
            {
                self.initial = Some(initial);
                Ok(())
            }
            Err(failure)
                if self.launch_failure.is_none()
                    && same_receipt(&failure.receipt, &self.receipt) =>
            {
                self.launch_failure = Some(failure);
                Ok(())
            }
            other => Err(Box::new(other)),
        }
    }
    pub fn has_cleanup_capability(&self) -> bool {
        self.initial.is_some()
            || self.mapped.is_some()
            || self.preparation_failure.is_some()
            || self.unconfirmed_initial.is_some()
            || self.launch_failure.is_some()
    }
    pub fn initial(&self) -> io::Result<&InitialExecStop<'fd>> {
        self.initial
            .as_ref()
            .ok_or_else(|| match self.launch_failure.as_ref() {
                Some(failure) => io::Error::other(format!("actual launch refused: {failure:?}")),
                None => invalid("actual initial stop absent"),
            })
    }
    pub fn mapped(&self) -> io::Result<&PreparedMapping<'fd>> {
        self.mapped
            .as_ref()
            .ok_or_else(|| invalid("actual prepared mapping absent"))
    }
    /// Prepare the retained initial stop's mapping, retaining whichever
    /// capability results.
    ///
    /// # Safety
    ///
    /// Exact existing Preparation contract, including original-thread
    /// affinity, inherited leases, real context/PKRU and external containment.
    /// Image execution qualification is NOT asserted by this map-only adapter.
    /// These are the obligations of [`InitialExecStop::prepare_mapping`].
    #[allow(unsafe_code)]
    pub unsafe fn prepare(&mut self, inputs: Preparation<'fd>) -> io::Result<()> {
        let initial = self
            .initial
            .take()
            .ok_or_else(|| invalid("actual initial stop absent"))?;
        // No await or fallible diagnostic between consuming and retaining owner.
        match unsafe { initial.prepare_mapping(inputs) } {
            Ok(mapped) => {
                self.mapped = Some(mapped);
                Ok(())
            }
            Err(failure) => {
                self.preparation_failure = Some(failure);
                match self.preparation_failure.as_ref() {
                    Some(retained) => Err(io::Error::other(format!(
                        "actual mapping refused: {}",
                        retained.error
                    ))),
                    None => Err(invalid("retained preparation failure absent")),
                }
            }
        }
    }
    pub fn retire_once(&mut self) {
        if let Some(initial) = self.initial.take()
            && let Err(owner) = initial.cancel()
        {
            self.unconfirmed_initial = Some(owner);
        }
        if let Some(mapped) = self.mapped.take() {
            match mapped.cancel() {
                Ok(cancelled) => self.cancelled = Some(cancelled),
                Err(mapped) => self.mapped = Some(*mapped),
            }
        }
        if let Some(failure) = self.preparation_failure.as_mut() {
            let _ = failure.retry_cleanup();
        }
        if let Some(failure) = self.launch_failure.as_mut() {
            let _ = failure.retry_cleanup();
        }
        if let Some(owner) = self.unconfirmed_initial.take()
            && let Err(owner) = (*owner).cancel()
        {
            self.unconfirmed_initial = Some(owner);
        }
    }
    /// The retained prepared mapping, mutably, if it is still held here.
    ///
    /// # Safety
    ///
    /// Use the mapping only through its own methods: never move it out,
    /// replace it or swap it (for example with `std::mem::swap` or
    /// `std::mem::replace`). Retirement confirms the child through this frame's
    /// receipt, so the mapping held here must stay the one this frame prepared.
    #[allow(unsafe_code)]
    pub unsafe fn mapped_mut(&mut self) -> Option<&mut PreparedMapping<'fd>> {
        self.mapped.as_mut()
    }
    /// Take the actual parent pipe endpoints from the initial stop, or else
    /// from the launch failure, if clone created them. This transfers no wait
    /// or cleanup authority.
    pub fn take_parent_stdio(&mut self) -> Option<reverie::process::ParentStdio> {
        self.initial
            .as_mut()
            .and_then(|stop| stop.take_parent_stdio())
            .or_else(|| {
                self.launch_failure
                    .as_mut()
                    .and_then(|failure| failure.take_parent_stdio())
            })
    }
    /// The frame's cleanup receipt (a shared handle to the same receipt).
    pub fn receipt(&self) -> &CleanupReceipt {
        &self.receipt
    }
    /// The confirmed cancellation transcript, once the mapping was retired.
    pub fn cancelled(&self) -> Option<&CancelledPreparation> {
        self.cancelled.as_ref()
    }
}
// No Drop success receipt, new reaper, raw task escape, wait loop, entry API,
// generic proof constructor or test suppression is added. The enclosing root
// MUST retain this component and all its leases until actual confirmed cleanup.

// A caught payload may have a panicking destructor. Retain the first payload
// (including an earlier setup/observation panic); never drop a secondary payload
// while actual child retirement is unconfirmed. This exceptional leak grants no
// cleanup credit. The containing fixture remains externally bounded.
pub type PanicPayload = Box<dyn std::any::Any + Send + 'static>;
pub fn retain_unwind<T>(
    first: &mut Option<PanicPayload>,
    operation: impl FnOnce() -> T,
) -> Option<T> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(value) => Some(value),
        Err(payload) => {
            if first.is_none() {
                *first = Some(payload);
            } else {
                std::mem::forget(payload);
            }
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementStep {
    Complete,
    RetryRetained,
    RetainFrame,
}

// This is host-side ownership control, not a terminal receipt constructor.
// The physical caller supplies the existing receipt snapshot and capability
// presence AFTER the caught attempt. Generic parameters permit data-only unwind
// tests to exercise this exact transition without manufacturing a ChildOwner.
pub fn guarded_retirement<T>(
    owner: &mut T,
    first: &mut Option<PanicPayload>,
    retire: impl FnOnce(&mut T),
    snapshot: impl FnOnce(&T) -> (bool, bool, bool),
) -> RetirementStep {
    let _ = retain_unwind(first, || retire(owner));
    let Some((created, confirmed, retained)) = retain_unwind(first, || snapshot(owner)) else {
        // An unreadable receipt provides no permission to release the frame.
        return RetirementStep::RetainFrame;
    };
    if !created || confirmed {
        RetirementStep::Complete
    } else if retained {
        RetirementStep::RetryRetained
    } else {
        RetirementStep::RetainFrame
    }
}

fn retain_unconfirmed_frame() -> ! {
    // Failure-only last resort: no diagnostics, TLS-dependent park, allocation,
    // callback, return, panic or resource destruction. Keep every outer backing,
    // descriptor/admission owner and caught payload live until the existing
    // whole-subtree containment terminates this FAILED/INCOMPLETE fixture. CPU
    // spin is deliberately limited to this lost-capability path, not retries.
    loop {
        std::hint::spin_loop();
    }
}

/// Retire both frames' retained capabilities until each completes.
///
/// # Safety
///
/// The caller's whole process subtree must be under external containment that
/// ends a frame which lost its capability: if a retirement can neither confirm
/// nor retain its capability, this never returns (it holds every backing,
/// descriptor and payload live, spinning, until that containment ends it).
///
/// Each frame must hold only capabilities of its own birth, as
/// [`RetainedPhysical`] keeps them: [`RetainedPhysical::retain_spawn`] refuses
/// any spawned with another receipt, and only a caller of the unsafe
/// [`RetainedPhysical::mapped_mut`] could move one between frames.
#[allow(unsafe_code)]
pub unsafe fn cleanup_all(
    a: &mut RetainedPhysical<'_>,
    b: &mut RetainedPhysical<'_>,
    first: &mut Option<PanicPayload>,
) {
    // No second wait/reaper, future, detach, entry or timeout release. Existing
    // R cancellation does its bounded original-owner wait. External containment
    // bounds this entire synchronous root if actual retirement never confirms.
    loop {
        let sa = guarded_retirement(
            a,
            first,
            |root| root.retire_once(),
            |root| {
                let state = root.receipt.snapshot();
                (
                    state.child_created,
                    state.confirmed,
                    root.has_cleanup_capability(),
                )
            },
        );
        let sb = guarded_retirement(
            b,
            first,
            |root| root.retire_once(),
            |root| {
                let state = root.receipt.snapshot();
                (
                    state.child_created,
                    state.confirmed,
                    root.has_cleanup_capability(),
                )
            },
        );
        if sa == RetirementStep::Complete && sb == RetirementStep::Complete {
            return;
        }
        if sa == RetirementStep::RetainFrame || sb == RetirementStep::RetainFrame {
            retain_unconfirmed_frame();
        }
        // Only actual retained capabilities are retried by retire_once. A lost
        // capability is never reconstructed from a PID, receipt or kill request.
    }
}

#[cfg(test)]
mod retention_tests;
