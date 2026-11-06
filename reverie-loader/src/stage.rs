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
//! let mapped = reverie_loader::stage::Mapped::from_mapped_stop(7u32);
//! let (_handed_off, stop) = mapped
//!     .runtime_started()
//!     .tool_ready()
//!     .armed()
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
/// init contract. Owns the stopped task `S`.
#[derive(Debug)]
#[must_use = "a ready stop must be advanced or torn down, not dropped silently"]
pub struct ToolReady<S>(S);

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
    /// init contract.
    pub fn tool_ready(self) -> ToolReady<S> {
        ToolReady(self.0)
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

    /// Every control the tool's manifest requires is armed. Callers
    /// must have established that — for example via
    /// [`crate::manifest::Controls::unmet`] returning `None` — before
    /// claiming this stage.
    pub fn armed(self) -> Armed<S> {
        Armed(self.0)
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

    #[derive(Debug, PartialEq, Eq)]
    struct DummyStop(u32);

    #[test]
    fn the_stages_chain_in_order_carrying_the_stop() {
        let mapped = Mapped::from_mapped_stop(DummyStop(1));
        let mut started = mapped.runtime_started();
        started.stop_mut().0 += 1;
        assert_eq!(started.stop(), &DummyStop(2));
        let (_done, stop) = started.tool_ready().armed().hand_over();
        assert_eq!(stop, DummyStop(2));
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
        assert_eq!(
            Mapped::from_mapped_stop(DummyStop(0))
                .runtime_started()
                .tool_ready()
                .into_stop(),
            DummyStop(0)
        );
        assert_eq!(
            Mapped::from_mapped_stop(DummyStop(0))
                .runtime_started()
                .tool_ready()
                .armed()
                .into_stop(),
            DummyStop(0)
        );
    }
}
