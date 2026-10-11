/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The only intended candidate seam. No keyed owner is implemented here.
//! Both adapters currently construct NRC19's actual ordinary key-zero owner.
//! A future candidate changes desired() only; legacy() and the oracle remain.

use super::super::super::ToolRegion;
use super::super::super::fixed_arena_backing;
use super::super::super::published_owner;
use super::BASE;
use super::CONTROL_BYTES;
use super::END;
use super::OwnerSnapshot;
use super::PAGE;
use super::SetupError;
use super::Span;
use super::raw;

pub(super) fn desired() -> Result<OwnerSnapshot, SetupError> {
    // Only this frozen construction seam changes from the archived baseline.
    use super::super::super::KeyedPrepareKind;
    use super::super::super::KeyedToolRegion;

    let owner = unsafe { KeyedToolRegion::reserve_native() }.map_err(|error| {
        if error.kind == KeyedPrepareKind::Unsupported {
            SetupError::unsupported(error.errno)
        } else {
            SetupError::error(error.errno)
        }
    })?;
    let spans = owner.spans();
    if spans.reservation.bottom != BASE
        || spans.reservation.top != END
        || spans.control.bottom != BASE + PAGE
        || spans.control.top != BASE + CONTROL_BYTES
        || spans.tool.bottom != BASE + 0x1000_0000
        || spans.tool.top != BASE + 0x1200_0000
        || spans.patch.bottom != BASE + 0x1400_0000
        || spans.patch.top != BASE + 0x1600_0000
    {
        return Err(SetupError::error(libc::EIO));
    }
    let lease =
        unsafe { owner.lease_stack(PAGE) }.map_err(|error| SetupError::error(error.errno))?;
    if !lease.belongs_to(owner) || lease.usable_bytes() != PAGE {
        return Err(SetupError::error(libc::EIO));
    }
    let stack = lease.retain();
    if !stack.belongs_to(owner) {
        return Err(SetupError::error(libc::EIO));
    }
    Ok(OwnerSnapshot {
        owner_identity: owner as *const KeyedToolRegion as usize,
        key: owner.key_descriptor().value(),
        reserved: 0,
        reservation: Span {
            bottom: spans.reservation.bottom,
            top: spans.reservation.top,
        },
        interiors: [
            Span {
                bottom: spans.control.bottom,
                top: spans.control.top,
            },
            Span {
                bottom: spans.tool.bottom,
                top: spans.tool.top,
            },
            Span {
                bottom: spans.patch.bottom,
                top: spans.patch.top,
            },
            Span {
                bottom: stack.base(),
                top: stack.top(),
            },
        ],
    })
}

pub(super) fn legacy() -> Result<OwnerSnapshot, SetupError> {
    // Allocate an unrelated unused key. Deliberately never rekey the targets.
    let key = raw(libc::SYS_pkey_alloc, [0; 6]);
    if key == -i64::from(libc::ENOSYS) {
        return Err(SetupError::unsupported(libc::ENOSYS));
    }
    if !(1..=15).contains(&key) {
        return Err(SetupError::error(if key < 0 {
            -key as i32
        } else {
            libc::EINVAL
        }));
    }
    let region = ToolRegion::reserve()
        .map_err(|error| SetupError::error(error.raw_os_error().unwrap_or(libc::EIO)))?;
    let published = published_owner().ok_or(SetupError::error(libc::EIO))?;
    if !core::ptr::eq(region, published) || region.control as usize != BASE + PAGE {
        return Err(SetupError::error(libc::EIO));
    }
    let backing = fixed_arena_backing().ok_or(SetupError::error(libc::EIO))?;
    if backing.tool_bottom != BASE + 0x1000_0000
        || backing.tool_top != BASE + 0x1200_0000
        || backing.patch_bottom != BASE + 0x1400_0000
        || backing.patch_top != BASE + 0x1600_0000
    {
        return Err(SetupError::error(libc::EIO));
    }
    let lease = region
        .stack(PAGE)
        .map_err(|error| SetupError::error(error.raw_os_error().unwrap_or(libc::EIO)))?;
    if !lease.belongs_to(region) || lease.usable_bytes() != PAGE {
        return Err(SetupError::error(libc::EIO));
    }
    let stack = Span {
        bottom: lease.base(),
        top: lease.top(),
    };
    let extent_start = (stack.bottom - BASE) / PAGE - 1;
    let extent_end = (stack.top - BASE) / PAGE + 1;
    {
        let mut held = region
            .lock()
            .map_err(|error| SetupError::error(error.raw_os_error().unwrap_or(libc::EIO)))?;
        let bitmap = held.bitmap();
        for page in extent_start..extent_end {
            if bitmap[page / 64] & (1_u64 << (page % 64)) == 0 {
                return Err(SetupError::error(libc::EIO));
            }
        }
    }
    let result = OwnerSnapshot {
        owner_identity: region as *const ToolRegion as usize,
        key: key as u32,
        reserved: 0,
        reservation: Span {
            bottom: BASE,
            top: END,
        },
        interiors: [
            Span {
                bottom: region.control as usize,
                top: BASE + CONTROL_BYTES,
            },
            Span {
                bottom: backing.tool_bottom,
                top: backing.tool_top,
            },
            Span {
                bottom: backing.patch_bottom,
                top: backing.patch_top,
            },
            stack,
        ],
    };
    // This actual occupied lease is retained until this disposable process
    // exits; it is never registered/running and never converted to ownership.
    core::mem::forget(lease);
    Ok(result)
}
