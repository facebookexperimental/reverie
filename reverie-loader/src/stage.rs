/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The loader's initialization stages as types (design section 3.4). Each
//! stage can only be reached from the one before it, by a function that
//! consumes the earlier stage, so the order "map, start the runtime, make
//! Detcore ready, arm, hand over" is enforced by the compiler rather than by
//! convention. The stages carry no data yet; the loader's steps attach what
//! each one proves as they are implemented.
//!
//! Only this crate can create or advance a stage, so no consumer can claim
//! a stage the loader has not reached:
//!
//! ```compile_fail,E0624
//! let _ = reverie_loader::stage::Mapped::after_mapping();
//! ```

/// The loader and runtime images are mapped at their fixed addresses.
#[derive(Debug)]
pub struct Mapped(());

/// The runtime has started on its own stack and TLS.
#[derive(Debug)]
pub struct RuntimeStarted(());

/// Detcore is initialized: root registration and the scheduler grant are
/// complete.
#[derive(Debug)]
pub struct DetcoreReady(());

/// The trap filter, the SIGSYS and SIGSEGV handlers, CPUID faulting, RDTSC
/// trapping and the vDSO rewrite are all in place.
#[derive(Debug)]
pub struct Armed(());

/// Control has passed to the image's own entry point. Nothing of the loader
/// runs after this.
#[derive(Debug)]
pub struct HandedOff(());

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the loader steps that produce each stage come with the mapper"
    )
)]
impl Mapped {
    /// The first stage. Only the loader's entry, after it has mapped and
    /// validated the images, may claim it.
    pub(crate) fn after_mapping() -> Self {
        Self(())
    }

    /// The runtime has started.
    pub(crate) fn runtime_started(self) -> RuntimeStarted {
        RuntimeStarted(())
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the loader steps that produce each stage come with the mapper"
    )
)]
impl RuntimeStarted {
    /// Detcore is ready.
    pub(crate) fn detcore_ready(self) -> DetcoreReady {
        DetcoreReady(())
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the loader steps that produce each stage come with the mapper"
    )
)]
impl DetcoreReady {
    /// Every control is armed.
    pub(crate) fn armed(self) -> Armed {
        Armed(())
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the loader steps that produce each stage come with the mapper"
    )
)]
impl Armed {
    /// Control has passed to the image.
    pub(crate) fn handed_off(self) -> HandedOff {
        HandedOff(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stages_chain_in_order() {
        let _done: HandedOff = Mapped::after_mapping()
            .runtime_started()
            .detcore_ready()
            .armed()
            .handed_off();
    }
}
