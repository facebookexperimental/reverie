//! Explicit per-image allocator selection. There is no default or weak owner.

use std::io;

use reverie_inguest::guest::alloc::legacy_tool_heap_bounds;
use reverie_inguest::guest::tool_region::fixed_arena_backing;

const VERSION: u64 = 1;
pub(crate) const LEGACY: u64 = 1;
pub(crate) const FIXED: u64 = 2;

/// Immutable link contract emitted beside the final image's compiler allocator.
///
/// Use an allocator declaration macro rather than constructing a declaration
/// separately. The runtime checks this contract before allocating, and artifact
/// qualification independently checks the actual compiler-selected routes.
#[doc(hidden)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AllocatorBackingDescriptor {
    version: u64,
    kind: u64,
}

impl AllocatorBackingDescriptor {
    /// Historical BSS backing for an explicitly declared embedded consumer.
    pub const fn legacy() -> Self {
        Self {
            version: VERSION,
            kind: LEGACY,
        }
    }

    /// Fixed backing for an image using the coupled fixed allocator declaration.
    pub const fn fixed() -> Self {
        Self {
            version: VERSION,
            kind: FIXED,
        }
    }
}

const _: () = {
    assert!(size_of::<AllocatorBackingDescriptor>() == 16);
    assert!(align_of::<AllocatorBackingDescriptor>() == 8);
};

unsafe extern "C" {
    static reverie_liteinst_allocator_backing_v1: AllocatorBackingDescriptor;
}

// Mark the reference hidden even when a consumer forgets its declaration.
// A retained reader must resolve inside its own image: a shared library cannot
// leave this as a dynamic undefined import satisfied by an unrelated preload.
core::arch::global_asm!(".hidden reverie_liteinst_allocator_backing_v1");

#[derive(Clone, Copy)]
pub(crate) struct SelectedBacking {
    #[cfg(feature = "allocator-fixture")]
    pub(crate) kind: u64,
    pub(crate) tool: (usize, usize),
    pub(crate) patch: (usize, usize),
}

impl SelectedBacking {
    pub(crate) fn contains(self, address: usize) -> bool {
        (self.tool.0..self.tool.1).contains(&address)
            || (self.patch.0..self.patch.1).contains(&address)
    }
}

fn backing_for(descriptor: AllocatorBackingDescriptor) -> io::Result<SelectedBacking> {
    if descriptor.version != VERSION {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    match descriptor.kind {
        LEGACY => Ok(SelectedBacking {
            #[cfg(feature = "allocator-fixture")]
            kind: LEGACY,
            tool: legacy_tool_heap_bounds(),
            patch: crate::patch_alloc::legacy_patch_heap_bounds(),
        }),
        FIXED => {
            let backing =
                fixed_arena_backing().ok_or_else(|| io::Error::from_raw_os_error(libc::EAGAIN))?;
            Ok(SelectedBacking {
                #[cfg(feature = "allocator-fixture")]
                kind: FIXED,
                tool: (backing.tool_bottom, backing.tool_top),
                patch: (backing.patch_bottom, backing.patch_top),
            })
        }
        _ => Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
    }
}

/// Read a required immutable declaration and already-published ownership only.
/// This cannot reserve a region or infer expected backing from an allocation.
pub(crate) fn selected_backing() -> io::Result<SelectedBacking> {
    // SAFETY: the final image supplies exactly one strong immutable descriptor.
    // Missing and duplicate declarations are link errors, not runtime fallbacks.
    // Keep the real read and its immutable storage in optimized/LTO images too;
    // the qualifier must inspect the descriptor rather than infer its existence.
    backing_for(unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(reverie_liteinst_allocator_backing_v1))
    })
}

/// Declare the compiler allocator and immutable backing contract of a true leaf.
///
/// Call exactly once at the final preload's crate root. It selects fixed Tool
/// arenas for every Rust allocation and requires authenticated initialization
/// before allocating; it does not cover allocations inside foreign libraries.
#[macro_export]
macro_rules! declare_fixed_tool_allocator {
    () => {
        #[global_allocator]
        static REVERIE_LITEINST_ALLOCATOR: $crate::FixedToolAllocator = $crate::FixedToolAllocator;
        #[used]
        #[unsafe(no_mangle)]
        static reverie_liteinst_allocator_backing_v1: $crate::AllocatorBackingDescriptor =
            $crate::AllocatorBackingDescriptor::fixed();
        core::arch::global_asm!(".hidden reverie_liteinst_allocator_backing_v1");
    };
}

/// Declare historical backing beside an existing custom or default allocator.
///
/// This does not make System or a custom allocator private. The real allocation
/// preflight still refuses an allocator which returns a non-Tool pointer.
#[macro_export]
macro_rules! declare_legacy_tool_backing {
    () => {
        #[used]
        #[unsafe(no_mangle)]
        static reverie_liteinst_allocator_backing_v1: $crate::AllocatorBackingDescriptor =
            $crate::AllocatorBackingDescriptor::legacy();
        core::arch::global_asm!(".hidden reverie_liteinst_allocator_backing_v1");
    };
}

/// Declare the historical always-private BSS allocator for an embedded image.
#[macro_export]
macro_rules! declare_legacy_private_tool_allocator {
    () => {
        #[global_allocator]
        static REVERIE_LITEINST_ALLOCATOR: $crate::PrivateToolAllocator =
            $crate::PrivateToolAllocator;
        $crate::declare_legacy_tool_backing!();
    };
}

/// Declare the historical scoped allocator for an embedded image.
/// Outside its installation/dispatch scopes this allocator retains System use.
#[macro_export]
macro_rules! declare_legacy_scoped_tool_allocator {
    () => {
        #[global_allocator]
        static REVERIE_LITEINST_ALLOCATOR: $crate::ScopedToolAllocator =
            $crate::ScopedToolAllocator;
        $crate::declare_legacy_tool_backing!();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_allocator_contracts_refuse() {
        for descriptor in [
            AllocatorBackingDescriptor {
                version: 0,
                kind: LEGACY,
            },
            AllocatorBackingDescriptor {
                version: VERSION,
                kind: 0,
            },
            AllocatorBackingDescriptor {
                version: VERSION + 1,
                kind: FIXED,
            },
        ] {
            assert_eq!(
                backing_for(descriptor).err().unwrap().raw_os_error(),
                Some(libc::EOPNOTSUPP)
            );
        }
    }
}
