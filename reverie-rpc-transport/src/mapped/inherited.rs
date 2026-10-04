/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fmt;
use std::io;
use std::mem::ManuallyDrop;
use std::sync::Arc;

use super::MappedStream;
use super::Mapping;

/// Why an inherited mapping remains owned instead of being released.
#[derive(Debug)]
pub enum InheritedMappingReleaseFailure {
    /// Another child-local strong reference still owns the mapping.
    Nonexclusive,
    /// The attempt to unmap the child-local VMA failed.
    Unmap(io::Error),
}

/// An owned, disarmed inherited mapping whose release has not succeeded.
///
/// This value cannot be used as a stream or restored to an endpoint. It never
/// closes, aborts, notifies or otherwise accesses the shared queues. Its
/// diagnostic operations use only cached local metadata.
///
/// Retain this owner and retry once the failure has been addressed, or account
/// for it as pending until actual process teardown. Dropping it releases its
/// local ownership with the mapping's ordinary best-effort destructor: the
/// last owner attempts local `munmap` and ignores its result. Dropping this
/// error therefore does **not** certify successful VMA release. Other local
/// aliases can also keep the mapping alive after this owner is dropped.
///
/// The private-memory and valid destruction-context requirements of
/// [`MappedStream::discard_inherited_after_fork`] continue to apply throughout
/// this owner's lifetime, including retry and destruction. Successful unmap
/// does not establish that a custom allocator reclaimed heap metadata.
#[must_use = "a failed inherited release retains ownership and requires explicit accounting"]
pub struct InheritedMappingReleaseError {
    pending: PendingMapping,
    failure: InheritedMappingReleaseFailure,
}

impl InheritedMappingReleaseError {
    /// The precise reason this owner remains pending.
    pub fn failure(&self) -> &InheritedMappingReleaseFailure {
        &self.failure
    }

    /// Retry releasing the same disarmed mapping; every failure retains it.
    ///
    /// # Safety
    /// The requirements of [`MappedStream::discard_inherited_after_fork`] must
    /// still hold, including private child-local ownership metadata, exclusion
    /// of queue use and alias creation, and a valid allocator/destruction
    /// context. All aliases must be under the caller's control. Do not retry
    /// after replacing or externally unmapping the cached address range.
    pub unsafe fn retry(self) -> Result<(), Self> {
        self.pending.release(unmap)
    }
}

impl fmt::Debug for InheritedMappingReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mapping = self.pending.mapping();
        f.debug_struct("InheritedMappingReleaseError")
            .field("failure", &self.failure)
            .field("address", &mapping.ptr)
            .field("length", &mapping.len)
            .finish()
    }
}

impl fmt::Display for InheritedMappingReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.failure {
            InheritedMappingReleaseFailure::Nonexclusive => {
                f.write_str("inherited mapped RPC release still has other local owners")
            }
            InheritedMappingReleaseFailure::Unmap(error) => {
                write!(f, "inherited mapped RPC unmap failed: {error}")
            }
        }
    }
}

impl std::error::Error for InheritedMappingReleaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.failure {
            InheritedMappingReleaseFailure::Nonexclusive => None,
            InheritedMappingReleaseFailure::Unmap(error) => Some(error),
        }
    }
}

impl MappedStream {
    /// Release only this process's inherited mapping without closing the stream.
    ///
    /// Consume the child's copy after a COW process fork, before any child use
    /// of the parent's endpoint. The parent's queues, flags and payload are
    /// untouched. Success means that the exact cached child-local VMA was
    /// successfully unmapped. Another strong owner or an unmap failure returns
    /// an owned, disarmed error that can be retried; it never returns a usable
    /// inherited endpoint. Normal endpoint destruction is unchanged.
    ///
    /// # Safety
    /// This must be the child's inherited copy after a process fork with
    /// private/COW address space, not a shared-VM clone or vfork-in-place. The
    /// stream, Arc allocation and Mapping metadata must reside in private/COW
    /// memory; the queue VMA itself remains shared with the parent and peer.
    /// An allocator that shares ownership metadata across processes does not
    /// satisfy this requirement.
    ///
    /// The caller must control every child-local alias and prevent concurrent
    /// or reentrant queue use, alias creation and external access to or
    /// replacement of the still-owned VMA. Successful release requires the
    /// sole remaining strong owner and no external raw/weak access that can
    /// outlive it. Copied references on vanished threads cannot be repaired by
    /// this operation. Controlled extra abort handles may be dropped without
    /// calling abort, then the disarmed error can be retried.
    ///
    /// Arc destruction can deallocate heap metadata. The caller must establish
    /// a valid allocator and destruction context; this operation does not make
    /// arbitrary allocators or user destructors safe after multithreaded fork.
    /// These obligations persist across a returned error, its retry and Drop.
    /// VMA release is separate from allocator-specific metadata reclamation.
    pub unsafe fn discard_inherited_after_fork(self) -> Result<(), InheritedMappingReleaseError> {
        disarm(self).release(unmap)
    }
}

// Suppress protocol-closing Drop before extracting the sole owned Arc. This
// helper also permits private tests to exercise a disarmed, quiescent endpoint
// without pretending that a libtest worker is an actual post-fork context.
fn disarm(stream: MappedStream) -> PendingMapping {
    let stream = ManuallyDrop::new(stream);
    let mapping = unsafe { std::ptr::read(&stream.mapping) };
    PendingMapping::Shared(mapping)
}

enum PendingMapping {
    Shared(Arc<Mapping>),
    Unique(Mapping),
}

impl PendingMapping {
    fn mapping(&self) -> &Mapping {
        match self {
            Self::Shared(mapping) => mapping,
            Self::Unique(mapping) => mapping,
        }
    }

    fn release(
        self,
        unmap: impl FnOnce(*mut libc::c_void, usize) -> io::Result<()>,
    ) -> Result<(), InheritedMappingReleaseError> {
        let mapping = match self {
            Self::Shared(mapping) => match Arc::try_unwrap(mapping) {
                Ok(mapping) => mapping,
                Err(mapping) => {
                    return Err(InheritedMappingReleaseError {
                        pending: Self::Shared(mapping),
                        failure: InheritedMappingReleaseFailure::Nonexclusive,
                    });
                }
            },
            Self::Unique(mapping) => mapping,
        };
        let mapping = ManuallyDrop::new(mapping);
        match unmap(mapping.ptr.as_ptr().cast(), mapping.len) {
            Ok(()) => Ok(()),
            Err(error) => Err(InheritedMappingReleaseError {
                pending: Self::Unique(ManuallyDrop::into_inner(mapping)),
                failure: InheritedMappingReleaseFailure::Unmap(error),
            }),
        }
    }
}

fn unmap(address: *mut libc::c_void, len: usize) -> io::Result<()> {
    if unsafe { libc::munmap(address, len) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests;
