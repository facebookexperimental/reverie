// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! The qualification claim for a mapped launch, kept apart from the launch.
//!
//! Arming never refuses a launch for a qualification gap: it always returns
//! the preparation and the entry. Whether the launch may be CALLED qualified is
//! a separate question, answered only by [`QualifiedMappedLaunch::claim`], the
//! one constructor of [`QualifiedMappedLaunch`]. Its inputs cannot be made up
//! by a caller: only arming builds a [`HandoffBinding`], from the handoff it
//! sealed and the [`MappedLaunchFacts`] of the bytes it mapped, and only an
//! [`AuditedRuntimeImage`](super::AuditedRuntimeImage) builds an audited
//! [`ArtifactAudit`]. The run label comes from [`launch_label`], which says
//! "mapped-qualified" only for a held claim.
//!
//! Today's handoff is UNBOUND AND UNQUALIFIED: its five binding digests
//! (launch, loader, runtime, source, layout) are all zero, byte-identical to
//! the wire this producer was promoted from, and the launch, loader and source
//! digests have no verifiable expected value yet. Every claim refuses with
//! [`HANDOFF_BINDING_UNBOUND`] until all five are written and verified.

use super::super::Result;
use super::super::physical::Preparation;
use super::super::physical::PreparedMapping;
use super::FilterCoverage;
use super::SyscallCensus;

/// A handoff binding digest is zero, or has no verifiable expected value.
pub const HANDOFF_BINDING_UNBOUND: &str = "exec_stop_handoff_binding_unbound";
/// The runtime binding digest is not the SHA-256 of the mapped runtime image.
pub const RUNTIME_DIGEST_MISMATCH: &str = "exec_stop_runtime_digest_mismatch";
/// The layout binding digest is not the SHA-256 of the image's 96-byte
/// HLMLAY01 descriptor.
pub const LAYOUT_DIGEST_MISMATCH: &str = "exec_stop_layout_digest_mismatch";
/// The runtime image did not pass the instruction audit and filter proof.
pub const RUNTIME_ARTIFACT_UNAUDITED: &str = "exec_stop_runtime_artifact_unaudited";

/// The five binding digest slots, in header order.
pub const BINDING_SLOTS: [&str; 5] = ["launch", "loader", "runtime", "source", "layout"];
const RUNTIME_SLOT: usize = 2;
const LAYOUT_SLOT: usize = 4;

/// One row of the qualification-gap catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QualificationGap {
    /// The refusal key a claim reports.
    pub key: &'static str,
    /// The predicate that, when true, refuses the claim.
    pub predicate: &'static str,
}

/// Every gap that refuses a qualification claim, in the order checked.
pub const QUALIFICATION_GAPS: [QualificationGap; 4] = [
    QualificationGap {
        key: RUNTIME_ARTIFACT_UNAUDITED,
        predicate: "the runtime image did not pass the instruction audit and the filter proof",
    },
    QualificationGap {
        key: HANDOFF_BINDING_UNBOUND,
        predicate: "a handoff binding digest is all-zero, or has no verifiable expected value",
    },
    QualificationGap {
        key: RUNTIME_DIGEST_MISMATCH,
        predicate: "binding digest 2 differs from SHA-256 of the mapped runtime image bytes",
    },
    QualificationGap {
        key: LAYOUT_DIGEST_MISMATCH,
        predicate: "binding digest 4 differs from SHA-256 of the mapped 96-byte layout descriptor",
    },
];

/// The expected value of each binding digest, from the bytes actually sealed
/// and mapped for one birth. A slot with no defined source of truth has none,
/// and so can never verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedLaunchFacts {
    expected: [Option<[u8; 32]>; 5],
}

impl MappedLaunchFacts {
    /// From the mapped runtime image's and its layout descriptor's SHA-256.
    /// The launch, loader and source digests have no defined source yet.
    pub(super) fn of_mapped(runtime_sha256: [u8; 32], layout_sha256: [u8; 32]) -> Self {
        let mut expected = [None; 5];
        expected[RUNTIME_SLOT] = Some(runtime_sha256);
        expected[LAYOUT_SLOT] = Some(layout_sha256);
        Self { expected }
    }

    /// The expected digest for `slot` (an index into [`BINDING_SLOTS`]).
    pub fn expected(&self, slot: usize) -> Option<[u8; 32]> {
        self.expected.get(slot).copied().flatten()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindingState {
    Bound,
    Zero(usize),
    Unverified(usize),
    Mismatch(usize),
}

/// What the sealed handoff's binding digests say about the mapped bytes.
/// Only arming builds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandoffBinding(BindingState);

impl HandoffBinding {
    /// Check each of the five digests (four little-endian words each), in
    /// slot order: it must be non-zero, have an expected value, and equal it.
    pub(super) fn of(binding: &[[u64; 4]; 5], facts: &MappedLaunchFacts) -> Self {
        for (slot, digest) in binding.iter().enumerate() {
            if digest == &[0; 4] {
                return Self(BindingState::Zero(slot));
            }
            let Some(expected) = facts.expected(slot) else {
                return Self(BindingState::Unverified(slot));
            };
            let words: [u64; 4] = std::array::from_fn(|i| {
                u64::from_le_bytes(expected[8 * i..8 * i + 8].try_into().expect("8 bytes"))
            });
            if digest != &words {
                return Self(BindingState::Mismatch(slot));
            }
        }
        Self(BindingState::Bound)
    }

    /// Whether all five digests are non-zero and verified.
    pub fn is_bound(&self) -> bool {
        self.0 == BindingState::Bound
    }

    /// The first slot that failed, and its refusal key; `None` when bound.
    pub fn refusal(&self) -> Option<(usize, &'static str)> {
        match self.0 {
            BindingState::Bound => None,
            BindingState::Zero(slot) | BindingState::Unverified(slot) => {
                Some((slot, HANDOFF_BINDING_UNBOUND))
            }
            BindingState::Mismatch(RUNTIME_SLOT) => Some((RUNTIME_SLOT, RUNTIME_DIGEST_MISMATCH)),
            BindingState::Mismatch(LAYOUT_SLOT) => Some((LAYOUT_SLOT, LAYOUT_DIGEST_MISMATCH)),
            // A slot with an expected value but no key of its own is unverified.
            BindingState::Mismatch(slot) => Some((slot, HANDOFF_BINDING_UNBOUND)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AuditState {
    Unaudited,
    Audited {
        census: SyscallCensus,
        filter: FilterCoverage,
    },
}

/// Whether the runtime image passed the instruction audit and filter proof.
/// Only an [`AuditedRuntimeImage`](super::AuditedRuntimeImage) produces the
/// audited form; any other image is [`ArtifactAudit::unaudited`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactAudit(AuditState);

impl ArtifactAudit {
    /// An image that did not go through the producer's audit.
    pub fn unaudited() -> Self {
        Self(AuditState::Unaudited)
    }

    pub(super) fn audited(census: SyscallCensus, filter: FilterCoverage) -> Self {
        Self(AuditState::Audited { census, filter })
    }

    /// The audit's counts, when the image was audited.
    pub fn counts(&self) -> Option<(&SyscallCensus, &FilterCoverage)> {
        match &self.0 {
            AuditState::Audited { census, filter } => Some((census, filter)),
            AuditState::Unaudited => None,
        }
    }
}

/// A refused qualification claim: the first gap found, and the binding slot
/// for a binding gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimRefusal {
    /// The catalog row that refused.
    pub gap: QualificationGap,
    /// The binding slot (an index into [`BINDING_SLOTS`]), for a binding gap.
    pub slot: Option<usize>,
}

impl std::fmt::Display for ClaimRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.gap.key, self.gap.predicate)?;
        if let Some(slot) = self.slot {
            write!(f, " (the {} digest)", BINDING_SLOTS[slot])?;
        }
        Ok(())
    }
}

impl std::error::Error for ClaimRefusal {}

/// The exact preparation inputs one claim belongs to: the addresses and
/// lengths of the runtime and handoff bytes, and the two child addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreparedIdentity {
    runtime: (usize, usize),
    handoff: (usize, usize),
    handoff_address: u64,
    layout_address: u64,
}

impl PreparedIdentity {
    fn of(preparation: &Preparation<'_>) -> Self {
        Self {
            runtime: (
                preparation.runtime_bytes.as_ptr() as usize,
                preparation.runtime_bytes.len(),
            ),
            handoff: (
                preparation.handoff_bytes.as_ptr() as usize,
                preparation.handoff_bytes.len(),
            ),
            handoff_address: preparation.handoff_address,
            layout_address: preparation.layout_address,
        }
    }
}

/// An armed birth's claim inputs, held until its preparation succeeds.
#[derive(Debug)]
pub struct ArmedClaim {
    binding: HandoffBinding,
    audit: ArtifactAudit,
    identity: PreparedIdentity,
}

impl ArmedClaim {
    pub(super) fn new(
        binding: HandoffBinding,
        audit: ArtifactAudit,
        preparation: &Preparation<'_>,
    ) -> Self {
        Self {
            binding,
            audit,
            identity: PreparedIdentity::of(preparation),
        }
    }

    /// The claim inputs, once `prepared` is the mapping made from exactly
    /// this birth's preparation (the same runtime and handoff bytes, the same
    /// handoff and layout addresses). Refuses any other mapping.
    pub fn after_prepare(self, prepared: &PreparedMapping<'_>) -> Result<MappedLaunchClaim> {
        if PreparedIdentity::of(prepared.inputs()) != self.identity {
            return Err("exec_stop_producer_claim_foreign_preparation".into());
        }
        Ok(MappedLaunchClaim {
            binding: self.binding,
            audit: self.audit,
        })
    }
}

/// The claim inputs of a birth whose preparation succeeded: what
/// [`QualifiedMappedLaunch::claim`] decides on. Only
/// [`ArmedClaim::after_prepare`] builds one.
#[derive(Debug)]
pub struct MappedLaunchClaim {
    binding: HandoffBinding,
    audit: ArtifactAudit,
}

impl MappedLaunchClaim {
    /// What the sealed handoff's binding digests say about the mapped bytes.
    pub fn binding(&self) -> &HandoffBinding {
        &self.binding
    }

    /// The image's audit.
    pub fn audit(&self) -> &ArtifactAudit {
        &self.audit
    }
}

/// Proof that a mapped launch may be labelled qualified. The only constructor
/// is [`QualifiedMappedLaunch::claim`].
#[derive(Debug)]
pub struct QualifiedMappedLaunch {
    _private: (),
}

impl QualifiedMappedLaunch {
    /// Claim qualification for a prepared launch. Refuses with the first
    /// catalog row whose predicate holds.
    pub fn claim(launch: &MappedLaunchClaim) -> std::result::Result<Self, ClaimRefusal> {
        let (binding, audit) = (&launch.binding, &launch.audit);
        let row = |key: &str| {
            *QUALIFICATION_GAPS
                .iter()
                .find(|row| row.key == key)
                .expect("every key has a catalog row")
        };
        if audit.counts().is_none() {
            return Err(ClaimRefusal {
                gap: row(RUNTIME_ARTIFACT_UNAUDITED),
                slot: None,
            });
        }
        match binding.refusal() {
            Some((slot, key)) => Err(ClaimRefusal {
                gap: row(key),
                slot: Some(slot),
            }),
            None => Ok(Self { _private: () }),
        }
    }
}

/// The label a mapped run reports: "mapped-qualified" only for a held claim,
/// otherwise "mapped-unqualified" with the refusal key and binding slot.
pub fn launch_label(claim: &std::result::Result<QualifiedMappedLaunch, ClaimRefusal>) -> String {
    match claim {
        Ok(_) => "mapped-qualified".into(),
        Err(refusal) => match refusal.slot {
            Some(slot) => format!(
                "mapped-unqualified:{}:{}",
                refusal.gap.key, BINDING_SLOTS[slot]
            ),
            None => format!("mapped-unqualified:{}", refusal.gap.key),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(digest: [u8; 32]) -> [u64; 4] {
        std::array::from_fn(|i| u64::from_le_bytes(digest[8 * i..8 * i + 8].try_into().unwrap()))
    }

    fn digest(slot: usize) -> [u8; 32] {
        [slot as u8 + 1; 32]
    }

    /// Facts with an expected value for every slot.
    fn every_slot_expected() -> MappedLaunchFacts {
        MappedLaunchFacts {
            expected: std::array::from_fn(|slot| Some(digest(slot))),
        }
    }

    fn bound() -> [[u64; 4]; 5] {
        std::array::from_fn(|slot| words(digest(slot)))
    }

    fn audited() -> ArtifactAudit {
        ArtifactAudit::audited(SyscallCensus::default(), FilterCoverage::default())
    }

    /// A claim as if its preparation succeeded.
    fn prepared(binding: HandoffBinding, audit: ArtifactAudit) -> MappedLaunchClaim {
        MappedLaunchClaim { binding, audit }
    }

    fn refusal(binding: &[[u64; 4]; 5], facts: &MappedLaunchFacts) -> ClaimRefusal {
        QualifiedMappedLaunch::claim(&prepared(HandoffBinding::of(binding, facts), audited()))
            .unwrap_err()
    }

    #[test]
    fn each_single_zero_digest_refuses_the_claim_as_unbound() {
        for slot in 0..5 {
            let mut binding = bound();
            binding[slot] = [0; 4];
            let refused = refusal(&binding, &every_slot_expected());
            assert_eq!(refused.gap.key, HANDOFF_BINDING_UNBOUND, "slot {slot}");
            assert_eq!(refused.slot, Some(slot));
        }
    }

    #[test]
    fn each_digest_without_an_expected_value_refuses_the_claim_as_unbound() {
        for slot in 0..5 {
            let mut facts = every_slot_expected();
            facts.expected[slot] = None;
            let refused = refusal(&bound(), &facts);
            assert_eq!(refused.gap.key, HANDOFF_BINDING_UNBOUND, "slot {slot}");
            assert_eq!(refused.slot, Some(slot));
        }
    }

    #[test]
    fn a_wrong_runtime_or_layout_digest_refuses_by_its_own_key() {
        let mut runtime = bound();
        runtime[RUNTIME_SLOT] = words([0xee; 32]);
        assert_eq!(
            refusal(&runtime, &every_slot_expected()).gap.key,
            RUNTIME_DIGEST_MISMATCH
        );
        let mut layout = bound();
        layout[LAYOUT_SLOT] = words([0xee; 32]);
        assert_eq!(
            refusal(&layout, &every_slot_expected()).gap.key,
            LAYOUT_DIGEST_MISMATCH
        );
        let mut launch = bound();
        launch[0] = words([0xee; 32]);
        assert_eq!(
            refusal(&launch, &every_slot_expected()).gap.key,
            HANDOFF_BINDING_UNBOUND
        );
    }

    #[test]
    fn todays_handoff_never_claims() {
        // What arming produces today: all-zero digests over mapped facts that
        // know only the runtime and layout digests.
        let facts = MappedLaunchFacts::of_mapped(digest(2), digest(4));
        let refused = refusal(&[[0; 4]; 5], &facts);
        assert_eq!(
            (refused.gap.key, refused.slot),
            (HANDOFF_BINDING_UNBOUND, Some(0))
        );
        // Even with every digest written correctly, launch has no expected value.
        let refused = refusal(&bound(), &facts);
        assert_eq!(
            (refused.gap.key, refused.slot),
            (HANDOFF_BINDING_UNBOUND, Some(0))
        );
    }

    #[test]
    fn a_claim_needs_an_audited_image_and_five_verified_digests() {
        let binding = HandoffBinding::of(&bound(), &every_slot_expected());
        assert!(binding.is_bound());
        let unaudited =
            QualifiedMappedLaunch::claim(&prepared(binding, ArtifactAudit::unaudited()));
        assert_eq!(
            unaudited.as_ref().unwrap_err().gap.key,
            RUNTIME_ARTIFACT_UNAUDITED
        );
        assert_eq!(
            launch_label(&unaudited),
            "mapped-unqualified:exec_stop_runtime_artifact_unaudited"
        );
        let held = QualifiedMappedLaunch::claim(&prepared(binding, audited()));
        assert!(held.is_ok());
        assert_eq!(launch_label(&held), "mapped-qualified");
        let zero = QualifiedMappedLaunch::claim(&prepared(
            HandoffBinding::of(&[[0; 4]; 5], &every_slot_expected()),
            audited(),
        ));
        assert_eq!(
            launch_label(&zero),
            "mapped-unqualified:exec_stop_handoff_binding_unbound:launch"
        );
    }

    #[test]
    fn every_key_has_exactly_one_catalog_row() {
        for key in [
            HANDOFF_BINDING_UNBOUND,
            RUNTIME_DIGEST_MISMATCH,
            LAYOUT_DIGEST_MISMATCH,
            RUNTIME_ARTIFACT_UNAUDITED,
        ] {
            assert_eq!(
                QUALIFICATION_GAPS
                    .iter()
                    .filter(|row| row.key == key)
                    .count(),
                1
            );
        }
    }
}
