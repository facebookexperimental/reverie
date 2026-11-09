/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Owned input pages and native-attempt accounting.
//!
//! These capabilities are deliberately not serializable. A Tool declares its
//! access and lifetime policy; the backend owns native task identities, stopped
//! execution, page initialization, and physical outcomes. Dropping a callback
//! must not discard an issued operation's obligations.

mod registry;
use std::sync::Arc;

pub use registry::*;

/// Address of the input facility, separate from executable and repair pages.
pub const RESERVED_INPUT_BASE: u64 = 0x7101_0000;

/// A request for the backend's fixed, sealed private input page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservedInputRequirement(());

impl ReservedInputRequirement {
    /// Request one native base page. The backend authenticates its layout.
    pub const fn sealed_page() -> Self {
        Self(())
    }
}

/// Native ABI whose pointer and page conventions were authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputAbi {
    /// Native 64-bit x86.
    X86_64,
    /// Native 64-bit Arm.
    Aarch64,
}

/// Actual authenticated private mapping. A layout is not write authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservedInputLayout {
    /// First byte of the backend-owned mapping.
    pub base: u64,
    /// Actual native base-page size.
    pub page_bytes: usize,
    /// Native guest ABI.
    pub abi: InputAbi,
}

impl ReservedInputLayout {
    /// Validate the fixed layout and checked extent, without claiming a VMA exists.
    pub fn validate(self) -> Result<Self, InputUnavailable> {
        if self.base != RESERVED_INPUT_BASE
            || !matches!(self.page_bytes, 4096 | 16384 | 65536)
            || self.base.checked_add(self.page_bytes as u64).is_none()
            || (self.abi == InputAbi::X86_64 && self.page_bytes != 4096)
        {
            return Err(InputUnavailable::new("input-layout-unsupported"));
        }
        Ok(self)
    }

    /// Whether the complete checked byte range belongs to this mapping.
    pub fn contains(self, address: u64, length: usize) -> bool {
        address >= self.base
            && address
                .checked_add(length as u64)
                .zip(self.base.checked_add(self.page_bytes as u64))
                .is_some_and(|(end, page_end)| end <= page_end)
    }

    /// Conservatively test every supported effective user-address spelling.
    ///
    /// This does not claim that a tagging mode is enabled. Linux arm64's
    /// `untagged_addr` removes the top byte only for the lower address half;
    /// x86 LAM U48/U57 remove bits 62:48/62:57 and preserve bit 63. A caller
    /// must not authorize a force-write merely because the raw spelling misses
    /// the page. An overflowing candidate is unknown, never disjoint.
    pub fn possibly_overlaps(self, address: u64, length: usize) -> Result<bool, InputUnavailable> {
        if length == 0 {
            return Ok(false);
        }
        let candidates = match self.abi {
            InputAbi::Aarch64 => {
                let untagged = if address & (1 << 55) == 0 {
                    address & 0x00ff_ffff_ffff_ffff
                } else {
                    address
                };
                [address, untagged, untagged]
            }
            InputAbi::X86_64 => [
                address,
                address & 0x8000_ffff_ffff_ffff,
                address & 0x81ff_ffff_ffff_ffff,
            ],
        };
        let page_end = self.base + self.page_bytes as u64;
        for start in candidates {
            let end = start
                .checked_add(length as u64)
                .ok_or_else(|| InputUnavailable::new("address-normalization-unavailable"))?;
            if start < page_end && end > self.base {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// A mechanism refusal with no application errno interpretation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct InputUnavailable {
    reason: Arc<str>,
}

impl InputUnavailable {
    /// Preserve a stable mechanism or policy reason supplied by its owner.
    pub fn new(reason: impl Into<Arc<str>>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Exact refusal reason, without replacing it with a guest errno.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Injection mechanism failure, separate from a native syscall's result.
#[derive(Debug, thiserror::Error)]
pub enum InputInjectionError {
    /// No native call ran and all altered state was verified settled.
    #[error("reserved input unavailable: {0}")]
    Unavailable(#[from] InputUnavailable),
    /// Ownership, normalization or continuation could not be proved safe.
    #[error("reserved input terminal failure: {0}")]
    Fatal(String),
}

/// One exact write in the future input image.
#[derive(Debug, Clone, Copy)]
pub struct InputWrite<'a> {
    /// Byte offset from the page's fixed base.
    pub offset: usize,
    /// Bytes copied into the immutable complete image.
    pub bytes: &'a [u8],
}

/// Complete immutable future image; unspecified bytes are zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedInputImage {
    layout: ReservedInputLayout,
    bytes: Arc<[u8]>,
}

impl ReservedInputImage {
    /// Build the exact image used by preparation reads and native readback.
    /// Overlapping writes are refused, even when their bytes happen to agree.
    pub fn new(
        layout: ReservedInputLayout,
        writes: &[InputWrite<'_>],
    ) -> Result<Self, InputUnavailable> {
        let layout = layout.validate()?;
        let mut bytes = vec![0; layout.page_bytes];
        let mut occupied = vec![false; layout.page_bytes];
        for write in writes {
            let end = write
                .offset
                .checked_add(write.bytes.len())
                .filter(|end| *end <= layout.page_bytes)
                .ok_or_else(|| InputUnavailable::new("input-image-range"))?;
            if occupied[write.offset..end].iter().any(|byte| *byte) {
                return Err(InputUnavailable::new("input-image-overlap"));
            }
            bytes[write.offset..end].copy_from_slice(write.bytes);
            occupied[write.offset..end].fill(true);
        }
        Ok(Self {
            layout,
            bytes: bytes.into(),
        })
    }

    /// Exact layout whose complete bytes this object describes.
    pub fn layout(&self) -> ReservedInputLayout {
        self.layout
    }

    /// Every byte to install, including the zeroed unused tail.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Read from the future image without touching the current guest mapping.
    pub fn read(&self, address: u64, output: &mut [u8]) -> bool {
        if !self.layout.contains(address, output.len()) {
            return false;
        }
        let start = (address - self.layout.base) as usize;
        output.copy_from_slice(&self.bytes[start..start + output.len()]);
        true
    }
}

/// Actual setup outcome for one target image, never the launch bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSetupOutcome {
    /// Mapping, permissions, sealing and stopped authority were authenticated.
    Qualified(ReservedInputLayout),
    /// This target image did not obtain the facility.
    Unqualified(InputUnavailable),
}

/// Synchronous observation made before the target's first instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSetupReceipt {
    /// Native task incarnation at the observation.
    pub task: InputTaskId,
    /// Actual setup, not configuration intent.
    pub outcome: InputSetupOutcome,
}

/// A physical query failed; absence of evidence is not a benign value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputNativeError {
    /// Native operation that failed.
    pub operation: &'static str,
    /// Native errno, when the interface supplied one.
    pub errno: Option<i32>,
}

/// Physical resource limit, before any Tool virtualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputNativeLimit {
    /// Current soft limit; u64::MAX denotes native infinity.
    pub current: u64,
    /// Maximum hard limit; u64::MAX denotes native infinity.
    pub maximum: u64,
}

/// Kernel-reported restartable-sequence registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputNativeRseq {
    /// Registered userspace address, zero if not registered.
    pub address: u64,
    /// Kernel-reported registration length.
    pub length: u32,
    /// Kernel-reported signature.
    pub signature: u32,
    /// Kernel-reported flags.
    pub flags: u32,
}

/// Native context in which procfd paths were rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputPathContext {
    /// Controller mount namespace identity.
    pub reader_mount_namespace: (u64, u64),
    /// Target mount namespace identity.
    pub target_mount_namespace: (u64, u64),
    /// Controller cgroup namespace used by cgroupfs path rendering.
    pub reader_cgroup_namespace: (u64, u64),
    /// Target cgroup namespace used by its mountinfo rendering.
    pub target_cgroup_namespace: (u64, u64),
    /// Controller root identity.
    pub reader_root: (u64, u64),
    /// Target root identity.
    pub target_root: (u64, u64),
}

impl InputPathContext {
    /// Equality required before combining a reader-rendered path with target mountinfo.
    pub fn same_view(&self) -> bool {
        self.reader_mount_namespace == self.target_mount_namespace
            && self.reader_cgroup_namespace == self.target_cgroup_namespace
            && self.reader_root == self.target_root
    }
}

/// Native descriptor identity from one pinned open-file description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputDescriptorFacts {
    /// Descriptor in the stopped task's native table.
    pub fd: i32,
    /// Native F_GETFL, including immutable access-mode bits.
    pub status_flags: Result<i32, InputNativeError>,
    /// Native F_GETSIG; owner interpretation remains the Tool's policy.
    pub async_signal: Result<i32, InputNativeError>,
    /// Native F_GETOWN_EX (owner type, namespace-relative numeric owner).
    pub async_owner: Result<(i32, i32), InputNativeError>,
    /// Native stat identity (device, inode, mode).
    pub identity: Result<(u64, u64, u32), InputNativeError>,
    /// Native filesystem magic.
    pub filesystem: Result<u64, InputNativeError>,
    /// Actual statx mount identifier when available.
    pub mount_id: Result<u64, InputNativeError>,
    /// Kernel-rendered procfd path; not by itself object classification.
    pub proc_path: Result<Vec<u8>, InputNativeError>,
    /// Exact reader/target context; a mismatch is not authenticated path equivalence.
    pub path_context: Result<InputPathContext, InputNativeError>,
}

/// Native duplicate retained through a synchronous Tool classifier.
#[derive(Debug)]
pub struct PinnedInputDescriptor {
    facts: InputDescriptorFacts,
    _pin: std::os::fd::OwnedFd,
}

impl PinnedInputDescriptor {
    /// Backend constructor after native description identity was verified.
    pub fn from_native_parts(facts: InputDescriptorFacts, pin: std::os::fd::OwnedFd) -> Self {
        Self { facts, _pin: pin }
    }
    /// Actual observations while the exact open-file description remains pinned.
    pub fn facts(&self) -> &InputDescriptorFacts {
        &self.facts
    }
}

impl std::ops::Deref for PinnedInputDescriptor {
    type Target = InputDescriptorFacts;
    fn deref(&self) -> &Self::Target {
        &self.facts
    }
}

/// A complete native descriptor census at an owned stop. Each item retains its
/// actual OFD pin; the mount text is rendered in the target's namespace.
#[derive(Debug)]
pub struct InputDescriptorSnapshot {
    /// Every actual descriptor enumerated and successfully pinned.
    pub descriptors: Vec<PinnedInputDescriptor>,
    /// Actual target mount table, never synthesized from descriptor names.
    pub mountinfo: Result<Vec<u8>, InputNativeError>,
}

/// Whether physical facts precede the launch exec or describe the target image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputImagePhase {
    /// The launcher has not executed its command; exec will reset native rseq.
    LaunchBootstrap,
    /// The actual target image, including a raw function with no launch exec.
    Target,
}

/// Owned-stop observations, made before any target callback can run.
#[derive(Debug)]
pub struct InputNativeFacts {
    /// Actual launch/image phase; not inferred from an empty thread state.
    pub phase: InputImagePhase,
    /// Exact task and mapping incarnation.
    pub task: InputTaskId,
    /// Physical RLIMIT_CPU.
    pub cpu: Result<InputNativeLimit, InputNativeError>,
    /// Physical RLIMIT_RTTIME.
    pub realtime: Result<InputNativeLimit, InputNativeError>,
    /// Actual native rseq registration.
    pub rseq: Result<InputNativeRseq, InputNativeError>,
    /// Complete native descriptor enumeration, or a failed census.
    pub descriptors: Result<Vec<PinnedInputDescriptor>, InputNativeError>,
    /// Native task mountinfo bytes, not the controller's view.
    pub mountinfo: Result<Vec<u8>, InputNativeError>,
    /// Task mount namespace device/inode.
    pub mount_namespace: Result<(u64, u64), InputNativeError>,
    /// Task root device/inode.
    pub root: Result<(u64, u64), InputNativeError>,
}

/// Tool admission of physical facts. The backend does not infer policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputAdmission {
    /// The Tool certified the facts required by its declared observation policy.
    Qualified,
    /// The Tool could not establish its required environment.
    Unqualified(InputUnavailable),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> ReservedInputLayout {
        ReservedInputLayout {
            base: RESERVED_INPUT_BASE,
            page_bytes: 4096,
            abi: InputAbi::X86_64,
        }
    }

    #[test]
    fn complete_image_has_one_future_view_and_no_hidden_padding() {
        let image = ReservedInputImage::new(
            layout(),
            &[InputWrite {
                offset: 9,
                bytes: &[3, 7, 2],
            }],
        )
        .unwrap();
        assert_eq!(image.bytes().len(), 4096);
        assert_eq!(&image.bytes()[9..12], &[3, 7, 2]);
        assert!(
            image.bytes()[..9]
                .iter()
                .chain(&image.bytes()[12..])
                .all(|byte| *byte == 0)
        );
        let mut future = [0; 8];
        assert!(image.read(RESERVED_INPUT_BASE + 7, &mut future));
        assert_eq!(future, [0, 0, 3, 7, 2, 0, 0, 0]);
        assert!(!image.read(RESERVED_INPUT_BASE + 4093, &mut future));
    }

    #[test]
    fn image_refuses_overlap_overflow_and_an_arbitrary_address() {
        assert!(
            ReservedInputImage::new(
                layout(),
                &[
                    InputWrite {
                        offset: 1,
                        bytes: &[1, 2]
                    },
                    InputWrite {
                        offset: 2,
                        bytes: &[2]
                    },
                ]
            )
            .is_err()
        );
        assert!(
            ReservedInputImage::new(
                layout(),
                &[InputWrite {
                    offset: usize::MAX,
                    bytes: &[1]
                }]
            )
            .is_err()
        );
        assert!(
            ReservedInputImage::new(
                ReservedInputLayout {
                    base: 0x1000,
                    ..layout()
                },
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn protected_range_includes_tag_aliases_and_full_breakpoint_word() {
        for abi in [InputAbi::X86_64, InputAbi::Aarch64] {
            let page = ReservedInputLayout { abi, ..layout() };
            for address in [page.base, page.base - 7, page.base + 4095] {
                assert!(
                    page.possibly_overlaps(address, 8).unwrap(),
                    "{abi:?} {address:#x}"
                );
            }
            assert!(!page.possibly_overlaps(page.base - 8, 8).unwrap());
            assert!(!page.possibly_overlaps(page.base + 4096, 8).unwrap());
            assert!(!page.possibly_overlaps(page.base + 10, 0).unwrap());
            assert!(page.possibly_overlaps(u64::MAX - 3, 8).is_err());
        }
        let x86 = layout();
        for tag in [1u64 << 48, 1 << 57, 0x7e00_0000_0000_0000] {
            assert!(x86.possibly_overlaps(x86.base | tag, 8).unwrap());
            assert!(!x86.possibly_overlaps((x86.base + 4096) | tag, 8).unwrap());
        }
        // Bit63 is not metadata in either LAM mode.
        assert!(!x86.possibly_overlaps(x86.base | (1 << 63), 8).unwrap());
        let arm = ReservedInputLayout {
            abi: InputAbi::Aarch64,
            ..layout()
        };
        for tag in [1u64, 0x80, 0xff] {
            assert!(arm.possibly_overlaps(arm.base | (tag << 56), 8).unwrap());
            assert!(
                !arm.possibly_overlaps((arm.base + 4096) | (tag << 56), 8)
                    .unwrap()
            );
        }
    }
}
