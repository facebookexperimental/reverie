/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The loader's initialization stages as types, carrying the stopped
//! task itself. Each stage owns a stopped-task handle `S` — whatever a
//! launcher uses to hold its tracee stopped at the exec boundary — and
//! can only be reached from the stage before it, by a method that
//! consumes the earlier stage. The order "map, start the runtime, make
//! the tool ready, arm, hand over" is therefore enforced by the
//! compiler rather than by convention, and the stop cannot be used
//! except through the stage that currently owns it:
//!
//! ```
//! let manifest = &reverie_loader::manifest::LOADER_MANIFEST;
//! let mapped = reverie_loader::stage::Mapped::from_mapped_stop(7u32);
//! let (_handed_off, stop) = mapped
//!     .runtime_started()
//!     .tool_ready(manifest, 0x1000, Some(0x1000))
//!     .expect("launched entry satisfies the manifest init contract")
//!     .armed(reverie_loader::manifest::Controls::NONE)
//!     .expect("every required control is armed")
//!     .hand_over();
//! assert_eq!(stop, 7);
//! ```
//!
//! Skipping a stage is a compile error — `Mapped` has no `armed`
//! method:
//!
//! ```compile_fail
//! fn skip<S>(mapped: reverie_loader::stage::Mapped<S>) {
//!     let _ = mapped.armed();
//! }
//! ```
//!
//! Reusing a consumed stage is a compile error too:
//!
//! ```compile_fail
//! fn reuse<S>(mapped: reverie_loader::stage::Mapped<S>) {
//!     let _started = mapped.runtime_started();
//!     let _again = mapped.runtime_started();
//! }
//! ```
//!
//! The chain orders a launcher's steps; it does not perform them.
//! Mapping, runtime start, tool readiness and arming are the
//! launcher's physical work, done while holding the stop through
//! [`Mapped::stop_mut`] and its siblings, and refusal at any step is
//! total: the launcher tears the stop down instead of advancing.
//! The transitions that claim init and arming take evidence — the
//! manifest plus the entry actually launched, and the controls
//! actually armed — and refuse by name, returning the stage, when
//! that evidence does not satisfy the manifest.

use crate::manifest::Control;
use crate::manifest::Controls;
use crate::manifest::InitRefusal;
use crate::manifest::ToolManifest;

/// The loader and runtime images are mapped at their fixed addresses.
/// Owns the stopped task `S`.
#[derive(Debug)]
#[must_use = "a mapped stop must be advanced or torn down, not dropped silently"]
pub struct Mapped<S>(S);

/// The runtime has started on its own stack and TLS. Owns the stopped
/// task `S`.
#[derive(Debug)]
#[must_use = "a started stop must be advanced or torn down, not dropped silently"]
pub struct RuntimeStarted<S>(S);

/// The tool is initialized: tool initialization has completed per its
/// init contract. Owns the stopped task `S`, and carries the controls
/// the manifest accepted by [`RuntimeStarted::tool_ready`] requires —
/// [`ToolReady::armed`] checks the observed controls against that
/// bound set, so a caller cannot re-derive "required" from what it
/// happened to arm.
#[derive(Debug)]
#[must_use = "a ready stop must be advanced or torn down, not dropped silently"]
pub struct ToolReady<S>(S, Controls);

/// Every control the tool's manifest requires is armed. Owns the
/// stopped task `S`.
#[derive(Debug)]
#[must_use = "an armed stop must be handed over or torn down, not dropped silently"]
pub struct Armed<S>(S);

/// Control has passed to the image's own entry point. Carries no stop:
/// [`Armed::hand_over`] returns the stop to its caller separately, for
/// the resume/detach the launcher performs next. Nothing of the loader
/// runs after this.
#[derive(Debug)]
pub struct HandedOff(());

impl<S> Mapped<S> {
    /// The first stage, from a stop the caller has already mapped.
    ///
    /// This constructor is the chain's trust boundary. The type system
    /// orders everything after it, but it cannot verify physical
    /// mapping: the caller asserts that `stop` is a genuinely mapped
    /// stop — the loader and runtime images were validated (see
    /// [`crate::artifact::check_image`]) and mapped at their fixed
    /// addresses, and no guest instruction has run since the exec
    /// boundary. Constructing a `Mapped` from an unmapped or
    /// already-running stop defeats the no-guest-instruction-before-arm
    /// guarantee the chain exists to enforce.
    pub fn from_mapped_stop(stop: S) -> Self {
        Self(stop)
    }

    /// The stopped task this stage owns.
    pub fn stop(&self) -> &S {
        &self.0
    }

    /// The stopped task this stage owns, mutably, for the physical
    /// work of the next step.
    pub fn stop_mut(&mut self) -> &mut S {
        &mut self.0
    }

    /// Gives the stop back without advancing — the teardown path.
    pub fn into_stop(self) -> S {
        self.0
    }

    /// The runtime has started on its own stack and TLS.
    pub fn runtime_started(self) -> RuntimeStarted<S> {
        RuntimeStarted(self.0)
    }
}

impl<S> RuntimeStarted<S> {
    /// The stopped task this stage owns.
    pub fn stop(&self) -> &S {
        &self.0
    }

    /// The stopped task this stage owns, mutably, for the physical
    /// work of the next step.
    pub fn stop_mut(&mut self) -> &mut S {
        &mut self.0
    }

    /// Gives the stop back without advancing — the teardown path.
    pub fn into_stop(self) -> S {
        self.0
    }

    /// The tool is ready: tool initialization has completed per its
    /// init contract. Takes evidence: the manifest, the checked
    /// image's entry point, and the entry the launcher actually
    /// launched (`None` if it launched nothing). Refuses by name,
    /// returning this stage for teardown, unless the launched
    /// entry is exactly what the manifest's init contract requires
    /// — an image is never silently run as if it had declared a
    /// different init. On success the manifest's required controls
    /// are bound into the returned stage.
    pub fn tool_ready(
        self,
        manifest: &ToolManifest,
        image_entry: u64,
        launched_entry: Option<u64>,
    ) -> Result<ToolReady<S>, (Self, InitRefusal)> {
        match manifest.check_init_entry(image_entry, launched_entry) {
            Ok(()) => Ok(ToolReady(self.0, manifest.controls)),
            Err(refusal) => Err((self, refusal)),
        }
    }
}

impl<S> ToolReady<S> {
    /// The stopped task this stage owns.
    pub fn stop(&self) -> &S {
        &self.0
    }

    /// The stopped task this stage owns, mutably, for the physical
    /// work of the next step.
    pub fn stop_mut(&mut self) -> &mut S {
        &mut self.0
    }

    /// Gives the stop back without advancing — the teardown path.
    pub fn into_stop(self) -> S {
        self.0
    }

    /// The controls the manifest accepted at `tool_ready` requires:
    /// the set [`armed`](Self::armed) checks the observed controls
    /// against.
    pub fn required_controls(&self) -> Controls {
        self.1
    }

    /// Every control the tool's manifest requires is armed. Takes
    /// evidence: only the controls actually observed armed. The
    /// required set is the one bound from the manifest when this
    /// stage was created — it is not a parameter, so a caller
    /// cannot satisfy the check by declaring whatever it armed to
    /// be what was required. Refuses by name, returning this stage
    /// for teardown, while any required control is unmet — the
    /// check lives here, in the loader, so a launcher cannot claim
    /// `Armed` without it succeeding.
    pub fn armed(self, observed: Controls) -> Result<Armed<S>, (Self, Control)> {
        match self.1.unmet(observed) {
            None => Ok(Armed(self.0)),
            Some(unmet) => Err((self, unmet)),
        }
    }
}

impl<S> Armed<S> {
    /// The stopped task this stage owns.
    pub fn stop(&self) -> &S {
        &self.0
    }

    /// The stopped task this stage owns, mutably, for the final
    /// restoration before handover.
    pub fn stop_mut(&mut self) -> &mut S {
        &mut self.0
    }

    /// Gives the stop back without handing over — the teardown path.
    pub fn into_stop(self) -> S {
        self.0
    }

    /// Hands control to the image: returns the terminal stage and the
    /// stop itself, which the launcher now resumes or detaches. The
    /// stop leaves the chain because after handover it is no longer
    /// the loader's to hold stopped.
    pub fn hand_over(self) -> (HandedOff, S) {
        (HandedOff(()), self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::InitContract;
    use crate::manifest::LOADER_MANIFEST;
    use crate::manifest::PROBE_RUNTIME_MANIFEST;

    #[derive(Debug, PartialEq, Eq)]
    struct DummyStop(u32);

    const ENTRY: u64 = 0x1000;

    fn ready(stop: DummyStop) -> ToolReady<DummyStop> {
        Mapped::from_mapped_stop(stop)
            .runtime_started()
            .tool_ready(&LOADER_MANIFEST, ENTRY, Some(ENTRY))
            .map_err(|(_stage, refusal)| refusal)
            .expect("image-entry init at the image entry")
    }

    fn probe_ready(stop: DummyStop) -> ToolReady<DummyStop> {
        Mapped::from_mapped_stop(stop)
            .runtime_started()
            .tool_ready(&PROBE_RUNTIME_MANIFEST, ENTRY, Some(ENTRY))
            .map_err(|(_stage, refusal)| refusal)
            .expect("probe image-entry init at the image entry")
    }

    #[test]
    fn the_stages_chain_in_order_carrying_the_stop() {
        let mapped = Mapped::from_mapped_stop(DummyStop(1));
        let mut started = mapped.runtime_started();
        started.stop_mut().0 += 1;
        assert_eq!(started.stop(), &DummyStop(2));
        let (_done, stop) = started
            .tool_ready(&LOADER_MANIFEST, ENTRY, Some(ENTRY))
            .map_err(|(_stage, refusal)| refusal)
            .expect("image-entry init at the image entry")
            .armed(Controls::NONE)
            .map_err(|(_stage, unmet)| unmet)
            .expect("no controls required")
            .hand_over();
        assert_eq!(stop, DummyStop(2));
    }

    #[test]
    fn tool_ready_refuses_an_init_entry_mismatch_by_name() {
        // ImageEntry declared, a different entry launched.
        let (stage, refusal) = Mapped::from_mapped_stop(DummyStop(3))
            .runtime_started()
            .tool_ready(&LOADER_MANIFEST, ENTRY, Some(ENTRY + 0x1000))
            .expect_err("mismatched entry must refuse");
        assert_eq!(
            refusal,
            InitRefusal::ExpectedImageEntry {
                image_entry: ENTRY,
                launched_entry: Some(ENTRY + 0x1000),
            }
        );
        assert_eq!(stage.into_stop(), DummyStop(3));
        // Address declared, the image entry launched instead.
        let mut address_manifest = LOADER_MANIFEST.clone();
        address_manifest.init = InitContract::Address(ENTRY + 0x2000);
        let (stage, refusal) = Mapped::from_mapped_stop(DummyStop(4))
            .runtime_started()
            .tool_ready(&address_manifest, ENTRY, Some(ENTRY))
            .expect_err("address init run as image entry must refuse");
        assert_eq!(
            refusal,
            InitRefusal::ExpectedAddress {
                address: ENTRY + 0x2000,
                launched_entry: Some(ENTRY),
            }
        );
        assert_eq!(stage.into_stop(), DummyStop(4));
        // None declared, an entry launched anyway.
        let mut none_manifest = LOADER_MANIFEST.clone();
        none_manifest.init = InitContract::None;
        let (stage, refusal) = Mapped::from_mapped_stop(DummyStop(5))
            .runtime_started()
            .tool_ready(&none_manifest, ENTRY, Some(ENTRY))
            .expect_err("no-init manifest entered anyway must refuse");
        assert_eq!(
            refusal,
            InitRefusal::ExpectedNoEntry {
                launched_entry: ENTRY,
            }
        );
        assert_eq!(stage.into_stop(), DummyStop(5));
    }

    #[test]
    fn armed_refuses_an_unmet_control_by_name() {
        // The required set is bound from the manifest `tool_ready`
        // accepted (the probe manifest requires the trap filter);
        // the caller supplies only what it observed armed.
        let required = PROBE_RUNTIME_MANIFEST.controls;
        let mut lacking_filter = required;
        lacking_filter.trap_filter = false;
        let (stage, unmet) = probe_ready(DummyStop(6))
            .armed(lacking_filter)
            .expect_err("observed controls lacking the trap filter must refuse");
        assert_eq!(unmet, Control::TrapFilter);
        // The stage is returned, so the stop remains teardown-able,
        // and the same stage succeeds once the evidence satisfies it.
        let (_done, stop) = stage
            .armed(required)
            .map_err(|(_stage, unmet)| unmet)
            .expect("exactly the required controls armed")
            .hand_over();
        assert_eq!(stop, DummyStop(6));
    }

    #[test]
    fn armed_is_bound_to_the_manifest_tool_ready_accepted() {
        // Same observed evidence (nothing armed), opposite verdicts:
        // the only difference is which manifest each `tool_ready`
        // accepted, so the required set cannot be coming from the
        // caller or from the observed set.
        let (_done, stop) = ready(DummyStop(7))
            .armed(Controls::NONE)
            .map_err(|(_stage, unmet)| unmet)
            .expect("loader manifest requires no controls")
            .hand_over();
        assert_eq!(stop, DummyStop(7));
        let probe = probe_ready(DummyStop(8));
        assert_eq!(probe.required_controls(), PROBE_RUNTIME_MANIFEST.controls);
        let (stage, unmet) = probe
            .armed(Controls::NONE)
            .expect_err("probe manifest controls unmet must refuse");
        assert_eq!(unmet, Control::TrapFilter);
        assert_eq!(stage.into_stop(), DummyStop(8));
    }

    #[test]
    fn every_stage_can_give_the_stop_back_for_teardown() {
        assert_eq!(
            Mapped::from_mapped_stop(DummyStop(0)).into_stop(),
            DummyStop(0)
        );
        assert_eq!(
            Mapped::from_mapped_stop(DummyStop(0))
                .runtime_started()
                .into_stop(),
            DummyStop(0)
        );
        assert_eq!(ready(DummyStop(0)).into_stop(), DummyStop(0));
        assert_eq!(
            ready(DummyStop(0))
                .armed(Controls::NONE)
                .map_err(|(_stage, unmet)| unmet)
                .expect("no controls required")
                .into_stop(),
            DummyStop(0)
        );
    }
}
