/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Where the loader and runtime images live, and the one check a built
//! image must pass before anything maps it.
//!
//! Both images are linked at fixed addresses inside Reverie's in-guest
//! `ToolRegion` reservation (`reverie-inguest`'s `tool_region::BASE..END`),
//! in a band near its top, clear of its control area and of its two fixed
//! arenas. Being inside the reservation is what keeps the guest from
//! mapping over them: the in-guest runtime refuses guest mapping calls that
//! touch `ToolRegion`. These constants are the source of truth for the
//! windows; `reverie-inguest`'s ToolRegion tests check them against its own
//! layout.
//!
//! The opt-in stage-1a probe maps these images inside its own fresh complete
//! reservation and uses only its separate test runtime. The production
//! ToolRegion fresh-owner bitmap permanently excludes the combined windows
//! and two exterior guard pages from general allocation. It leaves them
//! PROT_NONE and does not adopt this probe's loader-owned reservation or map
//! production images. The adjacent windows have no separate inner guard.
//! Production integration still requires authenticated adoption without
//! replacing live mappings, a precise mapped-image guard contract, genuine
//! runtime readiness and qualification of changed allocator artifacts with M1.
//! Bitmap exclusion and probe success do not satisfy those prerequisites or
//! activate a product backend.
//!
//! The first page of each window is that image's syscall gate: the only page
//! its `syscall` instructions may occupy, and so the only instruction
//! addresses the trap filter needs to allow. An image must map its gate page
//! executable and have at least one `syscall` in it.
//!
//! [`check`] parses, validates and audits an image's bytes in one call. A
//! build or launch step reads the image file and calls [`check_loader`] or
//! [`check_runtime`]; an image that fails is never mapped.

use core::ops::Range;

use crate::audit::SYSCALL;
use crate::audit::StraySyscall;
use crate::audit::stray_syscall;
use crate::image::Image;
use crate::image::ImageError;
use crate::image::PAGE_SIZE;
use crate::image::Policy;
use crate::image::ValidatedImage;
use crate::manifest::InitContract;
use crate::manifest::ManifestError;
use crate::manifest::ToolManifest;

/// Reverie's in-guest `ToolRegion` reservation, which both windows lie in.
pub const TOOL_REGION: Range<u64> = 0x6000_0000_0000..0x6001_0000_0000;

/// The loader image's window: 16 MiB at 3.5 GiB into [`TOOL_REGION`].
pub const LOADER_WINDOW: Range<u64> = 0x6000_e000_0000..0x6000_e100_0000;

/// The runtime image's window: 480 MiB from the end of [`LOADER_WINDOW`],
/// ending 16 MiB below the top of [`TOOL_REGION`]. The slot's debug runtime
/// is about 28 MB.
pub const RUNTIME_WINDOW: Range<u64> = 0x6000_e100_0000..0x6000_ff00_0000;

/// The loader's gate: the first page of [`LOADER_WINDOW`].
pub const LOADER_GATE: Range<u64> = LOADER_WINDOW.start..LOADER_WINDOW.start + PAGE_SIZE;

/// The runtime's gate: the first page of [`RUNTIME_WINDOW`].
pub const RUNTIME_GATE: Range<u64> = RUNTIME_WINDOW.start..RUNTIME_WINDOW.start + PAGE_SIZE;

/// The loader's policy: its window, and no TLS (it runs before any FS base
/// of its own exists).
pub const LOADER_POLICY: Policy = Policy {
    window: LOADER_WINDOW,
    allow_tls: false,
};

/// The runtime's policy: its window; TLS is allowed, on the runtime's own FS
/// base.
pub const RUNTIME_POLICY: Policy = Policy {
    window: RUNTIME_WINDOW,
    allow_tls: true,
};

const fn disjoint(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.end <= b.start || b.end <= a.start
}

const fn window_with_gate(window: &Range<u64>, gate: &Range<u64>) -> bool {
    window.start.is_multiple_of(PAGE_SIZE)
        && window.end.is_multiple_of(PAGE_SIZE)
        && window.start < window.end
        && gate.start == window.start
        && gate.end <= window.end
        && TOOL_REGION.start <= window.start
        && window.end <= TOOL_REGION.end
}

// The windows are page-aligned, start with their gates, lie inside the
// ToolRegion and not in each other.
const _: () = assert!(window_with_gate(&LOADER_WINDOW, &LOADER_GATE));
const _: () = assert!(window_with_gate(&RUNTIME_WINDOW, &RUNTIME_GATE));
const _: () = assert!(disjoint(&LOADER_WINDOW, &RUNTIME_WINDOW));

/// Why a built image may not be mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactError {
    /// The image failed parsing or validation.
    Image(ImageError),
    /// The image has a `syscall` encoding outside its gate.
    StraySyscall(StraySyscall),
    /// No executable segment maps the whole gate page.
    GateNotExecutable {
        /// The gate's first address.
        gate: u64,
    },
    /// The gate page holds no `syscall` encoding.
    NoGateSyscall {
        /// The gate's first address.
        gate: u64,
    },
    /// The manifest the image was checked against is not internally
    /// consistent.
    Manifest(ManifestError),
    /// The manifest's init address is not inside an executable segment
    /// of the image.
    InitNotExecutable {
        /// The init address.
        address: u64,
    },
}

impl From<ImageError> for ArtifactError {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

/// Parses `bytes`, validates the image against `policy`, requires each of
/// `gates` to be mapped executable with a `syscall` encoding wholly inside
/// it, and audits the image for `syscall` encodings outside `gates`. On
/// success the image may be mapped.
pub fn check<'a>(
    bytes: &'a [u8],
    policy: &Policy,
    gates: &[Range<u64>],
) -> Result<ValidatedImage<'a>, ArtifactError> {
    let image = Image::parse(bytes)?.validate(policy)?;
    for gate in gates {
        check_gate(&image, gate)?;
    }
    match stray_syscall(&image, gates)? {
        Some(stray) => Err(ArtifactError::StraySyscall(stray)),
        None => Ok(image),
    }
}

fn check_gate(image: &ValidatedImage<'_>, gate: &Range<u64>) -> Result<(), ArtifactError> {
    let not_executable = ArtifactError::GateNotExecutable { gate: gate.start };
    let mut covering = None;
    for segment in image.segments() {
        let pages = segment.pages()?;
        if segment.permissions.execute
            && !segment.permissions.write
            && pages.start <= gate.start
            && gate.end <= pages.end
        {
            covering = Some((segment, pages.start));
        }
    }
    let (segment, mapped_from) = covering.ok_or(not_executable)?;
    let bytes = image.mapped_file_bytes(segment)?;
    let offset = usize::try_from(gate.start - mapped_from).map_err(|_| ImageError::Overflow)?;
    let length = usize::try_from(gate.end - gate.start).map_err(|_| ImageError::Overflow)?;
    // Past the file bytes the mapping is zero, which holds no encoding.
    let inside = bytes
        .get(offset..)
        .map(|rest| &rest[..rest.len().min(length)])
        .unwrap_or(&[]);
    if inside.windows(2).any(|pair| pair == SYSCALL) {
        Ok(())
    } else {
        Err(ArtifactError::NoGateSyscall { gate: gate.start })
    }
}

impl From<ManifestError> for ArtifactError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

/// Checks `bytes` against a tool manifest: the manifest must
/// [`validate`](ToolManifest::validate), the image must pass [`check`]
/// under the manifest's policy and declared gates, and an
/// [`InitContract::Address`] must lie inside an executable segment of
/// the image (an [`InitContract::ImageEntry`] needs no extra check —
/// image validation already requires an executable entry). On success
/// the image may be mapped under this manifest.
///
/// This form assumes the loader's own [`PAGE_SIZE`]; a launcher on a
/// real host should call [`check_image_with_page_size`] with the
/// host page size so an unsupported host is refused by name here,
/// at image-check time, instead of being assumed away.
pub fn check_image<'a>(
    bytes: &'a [u8],
    manifest: &ToolManifest,
) -> Result<ValidatedImage<'a>, ArtifactError> {
    check_image_with_page_size(bytes, manifest, PAGE_SIZE)
}

/// [`check_image`] against an explicit host page size: the manifest
/// must [`validate_with_page_size`](ToolManifest::validate_with_page_size),
/// so any page size other than the one this x86-64 loader maps with
/// refuses as [`ManifestError::UnsupportedPageSize`] before the image
/// bytes are even parsed. The size is a parameter (this crate is
/// `no_std` and cannot ask the host) so the refused case is testable
/// without a 64 KiB-page host.
pub fn check_image_with_page_size<'a>(
    bytes: &'a [u8],
    manifest: &ToolManifest,
    page_size: u64,
) -> Result<ValidatedImage<'a>, ArtifactError> {
    manifest.validate_with_page_size(page_size)?;
    let image = check(bytes, &manifest.image.policy, manifest.gates)?;
    if let InitContract::Address(address) = manifest.init {
        let executable = image
            .segments()
            .any(|segment| segment.permissions.execute && segment.memory.contains(&address));
        if !executable {
            return Err(ArtifactError::InitNotExecutable { address });
        }
    }
    Ok(image)
}

/// [`check`] with the loader's policy and gate.
pub fn check_loader(bytes: &[u8]) -> Result<ValidatedImage<'_>, ArtifactError> {
    check(bytes, &LOADER_POLICY, core::slice::from_ref(&LOADER_GATE))
}

/// [`check`] with the runtime's policy and gate.
pub fn check_runtime(bytes: &[u8]) -> Result<ValidatedImage<'_>, ArtifactError> {
    check(bytes, &RUNTIME_POLICY, core::slice::from_ref(&RUNTIME_GATE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::tests::Phdr;
    use crate::image::tests::build;

    const PT_LOAD: u32 = 1;
    const RX: u32 = 4 | 1;
    const RW: u32 = 4 | 2;
    const GATE: u64 = RUNTIME_GATE.start;
    const TEXT: u64 = RUNTIME_GATE.end;

    /// An image with a gate segment (file offset 4096) and a text segment
    /// (file offset 8192); `body` starts at offset 4096.
    fn image(gate_flags: u32, body: &[u8]) -> Vec<u8> {
        let phdrs: [Phdr; 2] = [
            (PT_LOAD, gate_flags, 4096, GATE, 16, 16),
            (PT_LOAD, RX, 8192, TEXT, 16, 16),
        ];
        build(TEXT, &phdrs, body)
    }

    /// `gate` bytes at the gate, then `text` bytes at the text segment.
    fn body(gate: &[u8], text: &[u8]) -> Vec<u8> {
        let mut body = vec![0xc3u8; 4096 + 16];
        body[..gate.len()].copy_from_slice(gate);
        body[4096..4096 + text.len()].copy_from_slice(text);
        body
    }

    fn checked(bytes: &[u8]) -> Result<(), ArtifactError> {
        check_runtime(bytes).map(|_| ())
    }

    #[test]
    fn a_gate_with_its_syscall_and_clean_text_passes() {
        let bytes = image(RX, &body(&[0x0f, 0x05, 0xc3], &[0x90]));
        assert_eq!(checked(&bytes), Ok(()));
    }

    #[test]
    fn each_refusal_is_reported_by_name() {
        assert_eq!(
            checked(&[0u8; 10]),
            Err(ArtifactError::Image(ImageError::Truncated))
        );
        let stray = image(RX, &body(&[0x0f, 0x05], &[0x0f, 0x05]));
        assert_eq!(
            checked(&stray),
            Err(ArtifactError::StraySyscall(StraySyscall { address: TEXT }))
        );
        let readable_gate = image(4, &body(&[0x0f, 0x05], &[0x90]));
        assert_eq!(
            checked(&readable_gate),
            Err(ArtifactError::GateNotExecutable { gate: GATE })
        );
        let writable_gate = image(RW, &body(&[0x0f, 0x05], &[0x90]));
        assert_eq!(
            checked(&writable_gate),
            Err(ArtifactError::GateNotExecutable { gate: GATE })
        );
        let empty_gate = image(RX, &body(&[0x90], &[0x90]));
        assert_eq!(
            checked(&empty_gate),
            Err(ArtifactError::NoGateSyscall { gate: GATE })
        );
        // No segment at the gate at all, and no syscall anywhere.
        let gateless = build(
            TEXT,
            &[(PT_LOAD, RX, 8192, TEXT, 16, 16)],
            &body(&[], &[0x90]),
        );
        assert_eq!(
            checked(&gateless),
            Err(ArtifactError::GateNotExecutable { gate: GATE })
        );
        // The same image is outside the loader's window.
        let bytes = image(RX, &body(&[0x0f, 0x05], &[0x90]));
        assert_eq!(
            check_loader(&bytes).map(|_| ()),
            Err(ArtifactError::Image(ImageError::OutsideWindow { index: 0 }))
        );
    }

    #[test]
    fn check_image_agrees_with_check_runtime_and_check_loader() {
        use crate::manifest::LOADER_MANIFEST;
        use crate::manifest::PROBE_RUNTIME_MANIFEST;
        use crate::manifest::RUNTIME_MANIFEST;
        let good = image(RX, &body(&[0x0f, 0x05, 0xc3], &[0x90]));
        assert_eq!(check_image(&good, &RUNTIME_MANIFEST), check_runtime(&good));
        assert_eq!(
            check_image(&good, &PROBE_RUNTIME_MANIFEST),
            check_runtime(&good)
        );
        assert_eq!(check_image(&good, &LOADER_MANIFEST), check_loader(&good));
        let stray = image(RX, &body(&[0x0f, 0x05], &[0x0f, 0x05]));
        assert_eq!(
            check_image(&stray, &RUNTIME_MANIFEST),
            check_runtime(&stray)
        );
        assert_eq!(
            check_image(&[0u8; 10], &RUNTIME_MANIFEST),
            check_runtime(&[0u8; 10])
        );
    }

    #[test]
    fn check_image_refuses_a_bad_manifest_and_a_non_executable_init() {
        use crate::manifest::ManifestError;
        use crate::manifest::RUNTIME_MANIFEST;
        let bytes = image(RX, &body(&[0x0f, 0x05, 0xc3], &[0x90]));
        let mut no_gates = RUNTIME_MANIFEST.clone();
        no_gates.gates = &[];
        assert_eq!(
            check_image(&bytes, &no_gates).map(|_| ()),
            Err(ArtifactError::Manifest(ManifestError::NoGates))
        );
        // Inside the window but in no executable segment.
        let mut dead_init = RUNTIME_MANIFEST.clone();
        dead_init.init = InitContract::Address(TEXT + PAGE_SIZE);
        assert_eq!(
            check_image(&bytes, &dead_init).map(|_| ()),
            Err(ArtifactError::InitNotExecutable {
                address: TEXT + PAGE_SIZE
            })
        );
        // Inside the executable text segment: accepted.
        let mut live_init = RUNTIME_MANIFEST;
        live_init.init = InitContract::Address(TEXT);
        assert_eq!(check_image(&bytes, &live_init).map(|_| ()), Ok(()));
    }

    #[test]
    fn check_image_with_page_size_refuses_an_unsupported_host_by_name() {
        use crate::manifest::ManifestError;
        use crate::manifest::RUNTIME_MANIFEST;
        let bytes = image(RX, &body(&[0x0f, 0x05, 0xc3], &[0x90]));
        // A synthetic 64 KiB host page size refuses by name, before
        // the (valid) image bytes matter; the loader's own page
        // size accepts the same bytes.
        assert_eq!(
            check_image_with_page_size(&bytes, &RUNTIME_MANIFEST, 65_536).map(|_| ()),
            Err(ArtifactError::Manifest(
                ManifestError::UnsupportedPageSize { page_size: 65_536 }
            ))
        );
        assert_eq!(
            check_image_with_page_size(&bytes, &RUNTIME_MANIFEST, PAGE_SIZE).map(|_| ()),
            Ok(())
        );
        assert_eq!(
            check_image_with_page_size(&bytes, &RUNTIME_MANIFEST, PAGE_SIZE),
            check_image(&bytes, &RUNTIME_MANIFEST)
        );
    }

    #[test]
    fn an_encoding_straddling_the_gate_end_is_not_in_the_gate() {
        // The gate's last byte is 0f and the next page starts with 05: the
        // gate holds no whole encoding, and the straddling one is stray.
        let mut gate = vec![0xc3u8; 4096];
        gate[4095] = 0x0f;
        let mut body = vec![0xc3u8; 4096 + 16];
        body[..4096].copy_from_slice(&gate);
        body[4096] = 0x05;
        let phdrs: [Phdr; 2] = [
            (PT_LOAD, RX, 4096, GATE, 4096, 4096),
            (PT_LOAD, RX, 8192, TEXT, 16, 16),
        ];
        let bytes = build(TEXT, &phdrs, &body);
        assert_eq!(
            checked(&bytes),
            Err(ArtifactError::NoGateSyscall { gate: GATE })
        );
        let image = Image::parse(&bytes)
            .unwrap()
            .validate(&RUNTIME_POLICY)
            .unwrap();
        assert_eq!(
            stray_syscall(&image, core::slice::from_ref(&RUNTIME_GATE)),
            Ok(Some(StraySyscall {
                address: RUNTIME_GATE.end - 1
            }))
        );
    }
}
