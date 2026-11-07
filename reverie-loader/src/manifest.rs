/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! What a tool provides to the loader, as data only: one fixed-address
//! runtime image, its declared syscall gate ranges, the controls the
//! loader must arm before handoff, and how the tool is initialized.
//!
//! A manifest names no product and carries no authority: it is numbers
//! and extents a launcher checks ([`ToolManifest::validate`],
//! [`crate::artifact::check_image`]) and then acts on. Tool semantics —
//! what initialization *means* for a particular tool, which backend
//! mechanisms realize its controls — stay with the tool and the backend;
//! the loader neither knows nor names them.
//!
//! Isolation note (guarantee G5): tool windows live inside
//! [`crate::artifact::TOOL_REGION`] and the in-guest runtime refuses
//! guest mappings there. What the loader cannot itself guarantee —
//! hiding tool pages and descriptors from `/proc` and from probing — is
//! a **tool obligation**, stated here rather than silently assumed.
//! ToolRegion protection is a cooperative-guest boundary, not
//! automatically a hostile-code sandbox.

use core::ops::Range;

use crate::artifact::LOADER_GATE;
use crate::artifact::LOADER_POLICY;
use crate::artifact::RUNTIME_GATE;
use crate::artifact::RUNTIME_POLICY;
use crate::artifact::RUNTIME_WINDOW;
use crate::artifact::TOOL_REGION;
use crate::image::PAGE_SIZE;
use crate::image::Policy;

/// One declared syscall gate range: an address range whose pages may
/// execute `syscall` instructions.
pub type GateRange = Range<u64>;

/// The image half of a manifest: the validation policy (window and TLS)
/// the tool's runtime image must meet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageSpec {
    /// The policy [`crate::image::Image::validate`] applies.
    pub policy: Policy,
}

/// How the loader initializes the tool after mapping, before arming.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitContract {
    /// Run the image's own entry point; readiness is the image's to
    /// signal by its own convention.
    ImageEntry,
    /// Enter at this fixed address, which must lie in the image window
    /// and in an executable segment of the checked image.
    Address(u64),
    /// No loader-driven initialization; the image needs none.
    None,
}

/// One control the loader can arm, named for refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Control {
    /// The syscall trap filter.
    TrapFilter,
    /// CPUID faulting.
    CpuidFaulting,
    /// RDTSC/RDTSCP trapping.
    RdtscTrapping,
    /// The vDSO rewrite.
    VdsoRewrite,
    /// The SIGSYS handler.
    SigsysHandler,
    /// The SIGSEGV handler.
    SigsegvHandler,
}

/// The controls a tool asks the loader to arm before handoff.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Controls {
    /// Arm the syscall trap filter.
    pub trap_filter: bool,
    /// Arm CPUID faulting.
    pub cpuid_faulting: bool,
    /// Arm RDTSC/RDTSCP trapping.
    pub rdtsc_trapping: bool,
    /// Arm the vDSO rewrite.
    pub vdso_rewrite: bool,
    /// Install the SIGSYS handler.
    pub sigsys_handler: bool,
    /// Install the SIGSEGV handler.
    pub sigsegv_handler: bool,
}

impl Controls {
    /// No control requested.
    pub const NONE: Self = Self {
        trap_filter: false,
        cpuid_faulting: false,
        rdtsc_trapping: false,
        vdso_rewrite: false,
        sigsys_handler: false,
        sigsegv_handler: false,
    };

    /// Every control requested.
    pub const ALL: Self = Self {
        trap_filter: true,
        cpuid_faulting: true,
        rdtsc_trapping: true,
        vdso_rewrite: true,
        sigsys_handler: true,
        sigsegv_handler: true,
    };

    /// The first control this set requires that `armed` does not have,
    /// in field order, or `None` when every required control is armed.
    /// A launcher must refuse handoff while this returns `Some`
    /// (refusal is total: the guest never runs partially armed).
    pub const fn unmet(self, armed: Self) -> Option<Control> {
        // Destructure both sets so adding a control field without
        // handling it here is a compile error, not a silent pass.
        let Self {
            trap_filter,
            cpuid_faulting,
            rdtsc_trapping,
            vdso_rewrite,
            sigsys_handler,
            sigsegv_handler,
        } = self;
        let Self {
            trap_filter: armed_trap_filter,
            cpuid_faulting: armed_cpuid_faulting,
            rdtsc_trapping: armed_rdtsc_trapping,
            vdso_rewrite: armed_vdso_rewrite,
            sigsys_handler: armed_sigsys_handler,
            sigsegv_handler: armed_sigsegv_handler,
        } = armed;
        if trap_filter && !armed_trap_filter {
            return Some(Control::TrapFilter);
        }
        if cpuid_faulting && !armed_cpuid_faulting {
            return Some(Control::CpuidFaulting);
        }
        if rdtsc_trapping && !armed_rdtsc_trapping {
            return Some(Control::RdtscTrapping);
        }
        if vdso_rewrite && !armed_vdso_rewrite {
            return Some(Control::VdsoRewrite);
        }
        if sigsys_handler && !armed_sigsys_handler {
            return Some(Control::SigsysHandler);
        }
        if sigsegv_handler && !armed_sigsegv_handler {
            return Some(Control::SigsegvHandler);
        }
        None
    }
}

/// Why a manifest is not internally consistent. Each refusal is named;
/// none depends on any image bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestError {
    /// The image window is empty.
    EmptyWindow,
    /// The image window is not page-aligned at both ends.
    WindowMisaligned,
    /// The image window lies outside [`crate::artifact::TOOL_REGION`].
    WindowOutsideToolRegion,
    /// The manifest declares no gate ranges.
    NoGates,
    /// A gate range is empty.
    EmptyGate {
        /// Index of the gate in the manifest's gate slice.
        index: usize,
    },
    /// A gate range is not page-aligned at both ends.
    GateMisaligned {
        /// Index of the gate in the manifest's gate slice.
        index: usize,
    },
    /// A gate range lies outside the image window.
    GateOutsideWindow {
        /// Index of the gate in the manifest's gate slice.
        index: usize,
    },
    /// Two gate ranges overlap.
    OverlappingGates {
        /// Index of the earlier gate.
        first: usize,
        /// Index of the later gate.
        second: usize,
    },
    /// An [`InitContract::Address`] lies outside the image window.
    InitOutsideWindow {
        /// The init address.
        address: u64,
    },
    /// The page size is not the one this x86-64 loader maps with
    /// ([`crate::image::PAGE_SIZE`], 4 KiB). Returned by
    /// [`ToolManifest::validate_with_page_size`] so a launcher on a
    /// host with any other page size refuses by name instead of
    /// silently assuming 4 KiB alignment.
    UnsupportedPageSize {
        /// The page size that was supplied.
        page_size: u64,
    },
}

/// Why a launcher's actual init entry does not satisfy a manifest's
/// [`InitContract`]. Each refusal is named; a launcher must refuse
/// handoff (and, where it can, refuse before launching at all) rather
/// than run an image as if it had declared a different init.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitRefusal {
    /// The manifest requires the image entry, but the launcher
    /// entered (or would enter) somewhere else, or nowhere.
    ExpectedImageEntry {
        /// The checked image's entry point.
        image_entry: u64,
        /// The entry the launcher actually used, if any.
        launched_entry: Option<u64>,
    },
    /// The manifest requires a fixed init address, but the launcher
    /// entered (or would enter) somewhere else, or nowhere.
    ExpectedAddress {
        /// The declared init address.
        address: u64,
        /// The entry the launcher actually used, if any.
        launched_entry: Option<u64>,
    },
    /// The manifest requires no loader-driven entry, but the
    /// launcher entered (or would enter) the image.
    ExpectedNoEntry {
        /// The entry the launcher actually used.
        launched_entry: u64,
    },
    /// This launcher only honours [`InitContract::ImageEntry`] and
    /// the manifest declares a different init contract.
    UnsupportedInit {
        /// The declared init contract.
        init: InitContract,
    },
}

/// What a tool provides to the loader. Data only; see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolManifest {
    /// The runtime image's validation policy.
    pub image: ImageSpec,
    /// The declared syscall gate ranges: the only ranges allowed to
    /// execute `syscall`, proven by [`crate::audit`] at check time.
    pub gates: &'static [GateRange],
    /// The controls the loader must arm before handoff.
    pub controls: Controls,
    /// How the tool is initialized after mapping.
    pub init: InitContract,
}

impl ToolManifest {
    /// Checks the manifest against itself and
    /// [`crate::artifact::TOOL_REGION`]: the window is page-aligned,
    /// non-empty and inside the ToolRegion; at least one gate is
    /// declared, each gate is page-aligned, non-empty, inside the
    /// window and disjoint from every other gate; an
    /// [`InitContract::Address`] lies inside the window. Executability
    /// of an init address needs an image and is checked by
    /// [`crate::artifact::check_image`].
    pub fn validate(&self) -> Result<(), ManifestError> {
        self.validate_with_page_size(PAGE_SIZE)
    }

    /// [`validate`](Self::validate) against an explicit page size.
    ///
    /// This loader contract is x86-64 with 4 KiB pages only: image
    /// validation, gate pages and segment rounding all use
    /// [`crate::image::PAGE_SIZE`]. Taking the size as an input lets
    /// a launcher pass its host page size and get a named
    /// [`ManifestError::UnsupportedPageSize`] refusal on any other
    /// host (for example a 64 KiB-page host) instead of the 4 KiB
    /// assumption being baked in silently.
    pub fn validate_with_page_size(&self, page_size: u64) -> Result<(), ManifestError> {
        if page_size != PAGE_SIZE {
            return Err(ManifestError::UnsupportedPageSize { page_size });
        }
        let window = &self.image.policy.window;
        if window.is_empty() {
            return Err(ManifestError::EmptyWindow);
        }
        if !window.start.is_multiple_of(page_size) || !window.end.is_multiple_of(page_size) {
            return Err(ManifestError::WindowMisaligned);
        }
        if window.start < TOOL_REGION.start || window.end > TOOL_REGION.end {
            return Err(ManifestError::WindowOutsideToolRegion);
        }
        if self.gates.is_empty() {
            return Err(ManifestError::NoGates);
        }
        for (index, gate) in self.gates.iter().enumerate() {
            if gate.is_empty() {
                return Err(ManifestError::EmptyGate { index });
            }
            if !gate.start.is_multiple_of(page_size) || !gate.end.is_multiple_of(page_size) {
                return Err(ManifestError::GateMisaligned { index });
            }
            if gate.start < window.start || gate.end > window.end {
                return Err(ManifestError::GateOutsideWindow { index });
            }
            for (second, other) in self.gates.iter().enumerate().skip(index + 1) {
                if gate.start < other.end && other.start < gate.end {
                    return Err(ManifestError::OverlappingGates {
                        first: index,
                        second,
                    });
                }
            }
        }
        if let InitContract::Address(address) = self.init
            && !window.contains(&address)
        {
            return Err(ManifestError::InitOutsideWindow { address });
        }
        Ok(())
    }

    /// The entry a launcher must use to honour this manifest's init
    /// contract for an image whose entry point is `image_entry`:
    /// the image entry itself, the declared address, or no entry.
    pub const fn expected_init_entry(&self, image_entry: u64) -> Option<u64> {
        match self.init {
            InitContract::ImageEntry => Some(image_entry),
            InitContract::Address(address) => Some(address),
            InitContract::None => None,
        }
    }

    /// Refuses by name unless `launched_entry` is exactly the entry
    /// this manifest's init contract requires for `image_entry`.
    /// A launcher calls this with the entry it launched (or is
    /// about to launch); anything else means the image ran as if
    /// it had declared a different init.
    pub const fn check_init_entry(
        &self,
        image_entry: u64,
        launched_entry: Option<u64>,
    ) -> Result<(), InitRefusal> {
        match self.init {
            InitContract::ImageEntry => {
                if matches!(launched_entry, Some(entry) if entry == image_entry) {
                    Ok(())
                } else {
                    Err(InitRefusal::ExpectedImageEntry {
                        image_entry,
                        launched_entry,
                    })
                }
            }
            InitContract::Address(address) => {
                if matches!(launched_entry, Some(entry) if entry == address) {
                    Ok(())
                } else {
                    Err(InitRefusal::ExpectedAddress {
                        address,
                        launched_entry,
                    })
                }
            }
            InitContract::None => match launched_entry {
                None => Ok(()),
                Some(launched_entry) => Err(InitRefusal::ExpectedNoEntry { launched_entry }),
            },
        }
    }

    /// Refuses by name unless this manifest declares
    /// [`InitContract::ImageEntry`]. For launchers that only ever
    /// enter an image at its own entry point: any other contract
    /// is a named refusal, never silently run as `ImageEntry`.
    pub const fn require_image_entry_init(&self) -> Result<(), InitRefusal> {
        match self.init {
            InitContract::ImageEntry => Ok(()),
            init => Err(InitRefusal::UnsupportedInit { init }),
        }
    }
}

/// The loader image, expressed as a manifest. The loader is not a tool:
/// it requests no controls and runs from its own entry point. This
/// manifest exists so its image is checked through the same
/// [`crate::artifact::check_image`] path as any tool image.
pub const LOADER_MANIFEST: ToolManifest = ToolManifest {
    image: ImageSpec {
        policy: LOADER_POLICY,
    },
    gates: core::slice::from_ref(&LOADER_GATE),
    controls: Controls::NONE,
    init: InitContract::ImageEntry,
};

/// The production-shaped tool runtime, expressed as a manifest: the
/// runtime window with TLS allowed on its own FS base, its gate
/// page, every control armed before handoff, initialization from
/// its entry point. No launcher consumes this manifest yet; it is
/// the checked-in contract the production runtime image is checked
/// against (see `check_runtime` equivalence in `artifact` tests).
pub const RUNTIME_MANIFEST: ToolManifest = ToolManifest {
    image: ImageSpec {
        policy: RUNTIME_POLICY,
    },
    gates: core::slice::from_ref(&RUNTIME_GATE),
    controls: Controls::ALL,
    init: InitContract::ImageEntry,
};

/// The stage-1a probe's test runtime, expressed as a manifest. The
/// probe deliberately initializes no TLS and performs no vDSO rewrite;
/// every other control is armed and self-tested before handoff. This
/// preserves the probe's existing checked behavior exactly — it is a
/// separate manifest rather than a weakening of [`RUNTIME_MANIFEST`].
pub const PROBE_RUNTIME_MANIFEST: ToolManifest = ToolManifest {
    image: ImageSpec {
        policy: Policy {
            window: RUNTIME_WINDOW,
            allow_tls: false,
        },
    },
    gates: core::slice::from_ref(&RUNTIME_GATE),
    controls: Controls {
        trap_filter: true,
        cpuid_faulting: true,
        rdtsc_trapping: true,
        vdso_rewrite: false,
        sigsys_handler: true,
        sigsegv_handler: true,
    },
    init: InitContract::ImageEntry,
};

/// A minimal syscall-counting runtime, expressed as a manifest: the
/// runtime window with no TLS, its gate page, initialization from its
/// entry point, and only the two controls counting needs — the trap
/// filter and the SIGSYS handler that receives it. CPUID faulting and
/// RDTSC trapping are deliberately not requested: a counter subscribes
/// to syscalls only, and arming instruction controls would change the
/// guest's own execution (for example libc feature selection) relative
/// to an uninstrumented run, which would corrupt the count. This is a
/// separate manifest rather than a weakening of [`RUNTIME_MANIFEST`]
/// or [`PROBE_RUNTIME_MANIFEST`]: each checked-in manifest states
/// exactly the controls its image arms.
pub const COUNTER_RUNTIME_MANIFEST: ToolManifest = ToolManifest {
    image: ImageSpec {
        policy: Policy {
            window: RUNTIME_WINDOW,
            allow_tls: false,
        },
    },
    gates: core::slice::from_ref(&RUNTIME_GATE),
    controls: Controls {
        trap_filter: true,
        cpuid_faulting: false,
        rdtsc_trapping: false,
        vdso_rewrite: false,
        sigsys_handler: true,
        sigsegv_handler: false,
    },
    init: InitContract::ImageEntry,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::LOADER_WINDOW;
    use crate::artifact::RUNTIME_WINDOW;

    fn manifest(window: Range<u64>, gates: &'static [GateRange]) -> ToolManifest {
        ToolManifest {
            image: ImageSpec {
                policy: Policy {
                    window,
                    allow_tls: false,
                },
            },
            gates,
            controls: Controls::NONE,
            init: InitContract::None,
        }
    }

    #[test]
    fn the_checked_in_manifests_validate() {
        assert_eq!(LOADER_MANIFEST.validate(), Ok(()));
        assert_eq!(RUNTIME_MANIFEST.validate(), Ok(()));
        assert_eq!(PROBE_RUNTIME_MANIFEST.validate(), Ok(()));
        assert_eq!(COUNTER_RUNTIME_MANIFEST.validate(), Ok(()));
    }

    #[test]
    fn the_counter_manifest_requests_exactly_the_counting_controls() {
        // Same image shape as the probe runtime (runtime window, no
        // TLS, the runtime gate), but only the trap filter and its
        // SIGSYS handler: arming CPUID/RDTSC would perturb the guest
        // being counted.
        assert_eq!(
            COUNTER_RUNTIME_MANIFEST.image.policy,
            PROBE_RUNTIME_MANIFEST.image.policy
        );
        assert_eq!(COUNTER_RUNTIME_MANIFEST.gates, &[RUNTIME_GATE]);
        assert_eq!(COUNTER_RUNTIME_MANIFEST.init, InitContract::ImageEntry);
        let controls = COUNTER_RUNTIME_MANIFEST.controls;
        assert_eq!(
            controls,
            Controls {
                trap_filter: true,
                sigsys_handler: true,
                ..Controls::NONE
            }
        );
        // Refusal is total and named for either missing control, and
        // arming exactly the requested set satisfies the manifest
        // without any instruction control.
        assert_eq!(controls.unmet(Controls::NONE), Some(Control::TrapFilter));
        assert_eq!(
            controls.unmet(Controls {
                trap_filter: true,
                ..Controls::NONE
            }),
            Some(Control::SigsysHandler)
        );
        assert_eq!(controls.unmet(controls), None);
        assert_eq!(controls.unmet(Controls::ALL), None);
    }

    #[test]
    fn the_checked_in_manifests_carry_the_existing_constants() {
        // Full-content pins: every field of every checked-in manifest
        // (image policy, gates, controls, init) is asserted exactly,
        // so no field — in particular a probe/counter control bit —
        // can drift silently. Flipping e.g. the probe's
        // `trap_filter` to false must fail this test by name.
        assert_eq!(
            LOADER_MANIFEST,
            ToolManifest {
                image: ImageSpec {
                    policy: LOADER_POLICY,
                },
                gates: core::slice::from_ref(&LOADER_GATE),
                controls: Controls::NONE,
                init: InitContract::ImageEntry,
            }
        );
        assert_eq!(
            RUNTIME_MANIFEST,
            ToolManifest {
                image: ImageSpec {
                    policy: RUNTIME_POLICY,
                },
                gates: core::slice::from_ref(&RUNTIME_GATE),
                controls: Controls::ALL,
                init: InitContract::ImageEntry,
            }
        );
        assert_eq!(
            PROBE_RUNTIME_MANIFEST,
            ToolManifest {
                image: ImageSpec {
                    policy: Policy {
                        window: RUNTIME_WINDOW,
                        allow_tls: false,
                    },
                },
                gates: core::slice::from_ref(&RUNTIME_GATE),
                controls: Controls {
                    trap_filter: true,
                    cpuid_faulting: true,
                    rdtsc_trapping: true,
                    vdso_rewrite: false,
                    sigsys_handler: true,
                    sigsegv_handler: true,
                },
                init: InitContract::ImageEntry,
            }
        );
        assert_eq!(
            COUNTER_RUNTIME_MANIFEST,
            ToolManifest {
                image: ImageSpec {
                    policy: Policy {
                        window: RUNTIME_WINDOW,
                        allow_tls: false,
                    },
                },
                gates: core::slice::from_ref(&RUNTIME_GATE),
                controls: Controls {
                    trap_filter: true,
                    cpuid_faulting: false,
                    rdtsc_trapping: false,
                    vdso_rewrite: false,
                    sigsys_handler: true,
                    sigsegv_handler: false,
                },
                init: InitContract::ImageEntry,
            }
        );
        // The probe controls check can fail, by name, in field order:
        // it is not a tautology against Controls::ALL.
        let probe_controls = PROBE_RUNTIME_MANIFEST.controls;
        assert_eq!(probe_controls.unmet(Controls::NONE), Some(Control::TrapFilter));
        assert_eq!(
            probe_controls.unmet(Controls {
                trap_filter: true,
                ..Controls::NONE
            }),
            Some(Control::CpuidFaulting)
        );
        assert_eq!(probe_controls.unmet(probe_controls), None);
    }

    #[test]
    fn an_unsupported_page_size_is_refused_by_name() {
        assert_eq!(PROBE_RUNTIME_MANIFEST.validate_with_page_size(PAGE_SIZE), Ok(()));
        assert_eq!(
            PROBE_RUNTIME_MANIFEST.validate_with_page_size(65_536),
            Err(ManifestError::UnsupportedPageSize { page_size: 65_536 })
        );
        assert_eq!(
            COUNTER_RUNTIME_MANIFEST.validate_with_page_size(16_384),
            Err(ManifestError::UnsupportedPageSize { page_size: 16_384 })
        );
        assert_eq!(
            RUNTIME_MANIFEST.validate_with_page_size(0),
            Err(ManifestError::UnsupportedPageSize { page_size: 0 })
        );
    }

    #[test]
    fn an_init_entry_mismatch_is_refused_by_name() {
        let entry = 0x6000_e100_1000_u64;
        let mut m = manifest(LOADER_WINDOW, &[LOADER_GATE]);
        m.init = InitContract::ImageEntry;
        assert_eq!(m.expected_init_entry(entry), Some(entry));
        assert_eq!(m.check_init_entry(entry, Some(entry)), Ok(()));
        assert_eq!(
            m.check_init_entry(entry, Some(entry + 0x1000)),
            Err(InitRefusal::ExpectedImageEntry {
                image_entry: entry,
                launched_entry: Some(entry + 0x1000),
            })
        );
        assert_eq!(
            m.check_init_entry(entry, None),
            Err(InitRefusal::ExpectedImageEntry {
                image_entry: entry,
                launched_entry: None,
            })
        );
        assert_eq!(m.require_image_entry_init(), Ok(()));
        m.init = InitContract::Address(entry + 0x2000);
        assert_eq!(m.expected_init_entry(entry), Some(entry + 0x2000));
        assert_eq!(m.check_init_entry(entry, Some(entry + 0x2000)), Ok(()));
        assert_eq!(
            m.check_init_entry(entry, Some(entry)),
            Err(InitRefusal::ExpectedAddress {
                address: entry + 0x2000,
                launched_entry: Some(entry),
            })
        );
        assert_eq!(
            m.require_image_entry_init(),
            Err(InitRefusal::UnsupportedInit {
                init: InitContract::Address(entry + 0x2000),
            })
        );
        m.init = InitContract::None;
        assert_eq!(m.expected_init_entry(entry), None);
        assert_eq!(m.check_init_entry(entry, None), Ok(()));
        assert_eq!(
            m.check_init_entry(entry, Some(entry)),
            Err(InitRefusal::ExpectedNoEntry {
                launched_entry: entry,
            })
        );
        assert_eq!(
            m.require_image_entry_init(),
            Err(InitRefusal::UnsupportedInit {
                init: InitContract::None,
            })
        );
    }

    #[test]
    fn each_window_refusal_is_named() {
        let gate: &[GateRange] = &[LOADER_GATE];
        assert_eq!(
            manifest(LOADER_WINDOW.start..LOADER_WINDOW.start, gate).validate(),
            Err(ManifestError::EmptyWindow)
        );
        assert_eq!(
            manifest(LOADER_WINDOW.start + 1..LOADER_WINDOW.end, gate).validate(),
            Err(ManifestError::WindowMisaligned)
        );
        assert_eq!(
            manifest(TOOL_REGION.start - PAGE_SIZE..LOADER_WINDOW.end, gate).validate(),
            Err(ManifestError::WindowOutsideToolRegion)
        );
        assert_eq!(manifest(LOADER_WINDOW, gate).validate(), Ok(()));
    }

    #[test]
    fn each_gate_refusal_is_named() {
        const BASE: u64 = LOADER_WINDOW.start;
        const EMPTY_GATE: GateRange = BASE..BASE;
        const EMPTY: &[GateRange] = core::slice::from_ref(&EMPTY_GATE);
        const MISALIGNED_GATE: GateRange = BASE..BASE + 1;
        const MISALIGNED: &[GateRange] = core::slice::from_ref(&MISALIGNED_GATE);
        const OUTSIDE_GATE: GateRange = LOADER_WINDOW.end..LOADER_WINDOW.end + PAGE_SIZE;
        const OUTSIDE: &[GateRange] = core::slice::from_ref(&OUTSIDE_GATE);
        const G0: GateRange = BASE..BASE + 2 * PAGE_SIZE;
        const OVERLAP: &[GateRange] = &[G0, BASE + PAGE_SIZE..BASE + 3 * PAGE_SIZE];
        const ADJACENT: &[GateRange] = &[G0, BASE + 2 * PAGE_SIZE..BASE + 3 * PAGE_SIZE];
        assert_eq!(
            manifest(LOADER_WINDOW, &[]).validate(),
            Err(ManifestError::NoGates)
        );
        assert_eq!(
            manifest(LOADER_WINDOW, EMPTY).validate(),
            Err(ManifestError::EmptyGate { index: 0 })
        );
        assert_eq!(
            manifest(LOADER_WINDOW, MISALIGNED).validate(),
            Err(ManifestError::GateMisaligned { index: 0 })
        );
        assert_eq!(
            manifest(LOADER_WINDOW, OUTSIDE).validate(),
            Err(ManifestError::GateOutsideWindow { index: 0 })
        );
        assert_eq!(
            manifest(LOADER_WINDOW, OVERLAP).validate(),
            Err(ManifestError::OverlappingGates {
                first: 0,
                second: 1
            })
        );
        assert_eq!(manifest(LOADER_WINDOW, ADJACENT).validate(), Ok(()));
    }

    #[test]
    fn an_init_address_must_lie_in_the_window() {
        let mut m = manifest(LOADER_WINDOW, &[LOADER_GATE]);
        m.init = InitContract::Address(LOADER_WINDOW.start);
        assert_eq!(m.validate(), Ok(()));
        m.init = InitContract::Address(LOADER_WINDOW.end);
        assert_eq!(
            m.validate(),
            Err(ManifestError::InitOutsideWindow {
                address: LOADER_WINDOW.end
            })
        );
        m.init = InitContract::ImageEntry;
        assert_eq!(m.validate(), Ok(()));
    }

    #[test]
    fn unmet_names_the_first_missing_control_in_field_order() {
        assert_eq!(Controls::NONE.unmet(Controls::NONE), None);
        assert_eq!(Controls::ALL.unmet(Controls::ALL), None);
        assert_eq!(
            Controls::ALL.unmet(Controls::NONE),
            Some(Control::TrapFilter)
        );
        let mut armed = Controls::ALL;
        armed.rdtsc_trapping = false;
        armed.sigsegv_handler = false;
        assert_eq!(Controls::ALL.unmet(armed), Some(Control::RdtscTrapping));
        // A control not required is never reported, armed or not.
        let required = Controls {
            sigsegv_handler: true,
            ..Controls::NONE
        };
        assert_eq!(
            required.unmet(Controls::NONE),
            Some(Control::SigsegvHandler)
        );
        assert_eq!(required.unmet(required), None);
    }
}
