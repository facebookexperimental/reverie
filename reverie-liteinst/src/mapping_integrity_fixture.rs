//! Feature-only C entry points for bounded ToolRegion spare-lease controls.
//! These exports select this native root's actual Fixed Tool allocator backing.

use reverie_inguest::guest::tool_region::mapping_fixture;
pub use reverie_inguest::guest::tool_region::mapping_fixture::MappingFixtureSnapshot;

/// Prepare a real spare lease and a verified free extent after runtime setup.
///
/// # Safety
/// The caller satisfies [`mapping_fixture::prepare`]'s ordinary single-thread
/// and output-record contract; this image declares the Fixed Tool allocator.
/// Never invoke this export inside a callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m6_mapping_fixture_prepare(
    output: *mut MappingFixtureSnapshot,
    bytes: usize,
) -> i32 {
    unsafe { mapping_fixture::prepare(mapping_fixture::Backing::Fixed, output, bytes) }
}

/// Observe the retained spare-lease and publication facts without mutation.
///
/// # Safety
/// The caller satisfies [`mapping_fixture::observe`]'s contract in this Fixed image.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m6_mapping_fixture_observe(
    output: *mut MappingFixtureSnapshot,
    bytes: usize,
) -> i32 {
    unsafe { mapping_fixture::observe(mapping_fixture::Backing::Fixed, output, bytes) }
}

/// Lease/reprotect/reset the originally observed free extent via trusted APIs.
///
/// # Safety
/// The caller satisfies [`mapping_fixture::reuse`]'s contract in this Fixed image.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m6_mapping_fixture_reuse(
    output: *mut MappingFixtureSnapshot,
    bytes: usize,
) -> i32 {
    unsafe { mapping_fixture::reuse(mapping_fixture::Backing::Fixed, output, bytes) }
}

/// Release only the fixture's own spare lease and its retained Tool state.
///
/// # Safety
/// The caller satisfies [`mapping_fixture::finish`]'s contract in this Fixed image.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m6_mapping_fixture_finish() -> i32 {
    unsafe { mapping_fixture::finish(mapping_fixture::Backing::Fixed) }
}
