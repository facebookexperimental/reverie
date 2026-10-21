//! Feature-only bounded spare-lease controls for real VM forwarding tests.
//!
//! These actions never reserve an owner, issue a caller-selected raw syscall,
//! or lease from a callback. A trusted single-thread caller invokes them after
//! the runtime's default alternate stack is registered. The diagnostic locator
//! is outside the fixed-storage claim, as are the existing fixture locators;
//! its retained state is allocated through the image's real Tool allocator.

use core::mem::align_of;
use core::mem::size_of;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;

use super::PAGE;
use super::REGION;
use super::StackLease;
use super::ToolRegion;
use crate::guest::alloc;
use crate::guest::support::tool_callback_active;
use crate::trap::raw_syscall6;

/// Initial byte in the separate live RW lease, read by the real Guest fixture.
pub const SENTINEL: u8 = 0x6d;

/// The actual compiler-selected Tool allocator of this fixture's image.
///
/// This is a diagnostic caller contract, not allocator discovery. Each variant
/// checks exactly its own backing; an address rejected there has no fallback.
#[derive(Clone, Copy, Debug)]
pub enum Backing {
    /// The embedded image explicitly declares the Legacy scoped Tool allocator.
    Legacy,
    /// The native runtime image explicitly declares the Fixed Tool allocator.
    Fixed,
}

impl Backing {
    fn require_state_address(self, pointer: *const u8) -> Result<(), i32> {
        let owned = match self {
            Self::Legacy => alloc::tool_heap_contains(pointer),
            Self::Fixed => alloc::fixed_tool_heap_contains(pointer),
        };
        if owned { Ok(()) } else { Err(libc::EFAULT) }
    }
}

/// Fixed-width observation; addresses come from actual retained lease objects.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[allow(missing_docs)]
pub struct MappingFixtureSnapshot {
    pub version: u64,
    pub owner: u64,
    pub control: u64,
    pub state: u64,
    pub current_pid: u64,
    pub current_tid: u64,
    pub alt_bottom: u64,
    pub alt_top: u64,
    pub live_base: u64,
    pub live_bytes: u64,
    pub live_guard_low: u64,
    pub live_guard_high: u64,
    pub live_owned: u64,
    pub free_base: u64,
    pub free_bytes: u64,
    pub free_guard_low: u64,
    pub free_guard_high: u64,
    pub free_unowned: u64,
    pub sentinel_expected: u64,
    pub reuse_base: u64,
    pub reuse_count: u64,
}

struct State {
    region: &'static ToolRegion,
    live: StackLease,
    free_start: usize,
    free_pages: usize,
    reuse_base: usize,
    reuse_count: u64,
}

// Single fixture per image/process. The nonwaiting gate is released at every
// action return; no State/bitmap borrow spans any Guest/Tool dispatch or fork.
static STATE: AtomicPtr<State> = AtomicPtr::new(core::ptr::null_mut());
static HELD: AtomicBool = AtomicBool::new(false);

struct Action;

impl Action {
    fn acquire() -> Result<Self, i32> {
        if tool_callback_active() || alloc::fixture_dispatch_depth() != 0 {
            return Err(libc::EBUSY);
        }
        HELD.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| libc::EAGAIN)?;
        Ok(Self)
    }
}

impl Drop for Action {
    fn drop(&mut self) {
        HELD.store(false, Ordering::Release);
    }
}

fn error_number(error: std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(libc::EIO)
}

fn published_owner() -> Result<&'static ToolRegion, i32> {
    match REGION.get() {
        Some(Ok(region)) => Ok(region),
        Some(Err(error)) => Err(*error),
        None => Err(libc::EAGAIN),
    }
}

fn range_is(region: &ToolRegion, start: usize, pages: usize, occupied: bool) -> Result<bool, i32> {
    let mut guard = region.lock().map_err(error_number)?;
    let bitmap = guard.bitmap();
    Ok((start..start + pages)
        .all(|page| (bitmap[page / 64] & (1_u64 << (page % 64)) != 0) == occupied))
}

fn output_valid(output: *mut MappingFixtureSnapshot, bytes: usize) -> bool {
    !output.is_null()
        && bytes == size_of::<MappingFixtureSnapshot>()
        && (output as usize).is_multiple_of(align_of::<MappingFixtureSnapshot>())
}

fn snapshot(state: &State) -> Result<MappingFixtureSnapshot, i32> {
    let owner = published_owner()?;
    if !core::ptr::eq(owner, state.region) || !state.live.belongs_to(owner) {
        return Err(libc::ESTALE);
    }
    let alternate = owner.registered_alternate_stack().ok_or(libc::EAGAIN)?;
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
    if pid <= 0 || tid != pid {
        return Err(libc::ENOTSUP);
    }
    let live_base = state.live.base();
    let free_base = super::BASE + (state.free_start + 1) * PAGE;
    Ok(MappingFixtureSnapshot {
        version: 1,
        owner: owner as *const ToolRegion as u64,
        control: owner.control as u64,
        state: state as *const State as u64,
        current_pid: pid as u64,
        current_tid: tid as u64,
        alt_bottom: alternate.bottom as u64,
        alt_top: alternate.top as u64,
        live_base: live_base as u64,
        live_bytes: state.live.usable_bytes() as u64,
        live_guard_low: (live_base - PAGE) as u64,
        live_guard_high: state.live.top() as u64,
        live_owned: u64::from(range_is(owner, state.live.start, state.live.pages, true)?),
        free_base: free_base as u64,
        free_bytes: ((state.free_pages - 2) * PAGE) as u64,
        free_guard_low: (free_base - PAGE) as u64,
        free_guard_high: (free_base + (state.free_pages - 2) * PAGE) as u64,
        free_unowned: u64::from(range_is(owner, state.free_start, state.free_pages, false)?),
        sentinel_expected: u64::from(SENTINEL),
        reuse_base: state.reuse_base as u64,
        reuse_count: state.reuse_count,
    })
}

unsafe fn current_state(_action: &mut Action, backing: Backing) -> Result<&mut State, i32> {
    let pointer = STATE.load(Ordering::Acquire);
    if pointer.is_null() {
        return Err(libc::ENODATA);
    }
    // Refuse the wrong backing before reading any State field or header.
    backing.require_state_address(pointer.cast())?;
    // SAFETY: a successful prepare published this Tool-scoped Box. _action
    // exclusively owns HELD; no caller receives this reference or keeps it.
    Ok(unsafe { &mut *pointer })
}

/// Prepare spare pages after runtime stack setup; never creates an owner.
///
/// # Safety
/// The caller runs in ordinary single-thread setup, outside signal handlers and
/// callbacks. `output` is one complete writable nonaliasing Guest record. The
/// caller names the image's actual compiler-selected Tool allocator in `backing`
/// (Legacy for an embedded scoped image, Fixed for a native Fixed root). The
/// same backing is used for every action; no System or other-backing fallback
/// is supplied. Passing another backing is refused before retained-State reads.
pub unsafe fn prepare(backing: Backing, output: *mut MappingFixtureSnapshot, bytes: usize) -> i32 {
    if !output_valid(output, bytes) {
        return -libc::EINVAL;
    }
    let result = (|| {
        let _action = Action::acquire()?;
        if !STATE.load(Ordering::Acquire).is_null() {
            return Err(libc::EALREADY);
        }
        let region = published_owner()?;
        // This fixture's contract requires stack setup first. It does not
        // restrict the runtime policy's broader owner/no-altstack contract.
        region.registered_alternate_stack().ok_or(libc::EAGAIN)?;
        let live = region.stack(PAGE).map_err(error_number)?;
        unsafe { (live.base() as *mut u8).write_volatile(SENTINEL) };
        let free = region.stack(PAGE).map_err(error_number)?;
        let free_start = free.start;
        let free_pages = free.pages;
        drop(free);
        if !range_is(region, free_start, free_pages, false)? {
            return Err(libc::EIO);
        }
        let _allocation = alloc::enter_dispatch();
        let state = Box::new(State {
            region,
            live,
            free_start,
            free_pages,
            reuse_base: 0,
            reuse_count: 0,
        });
        let pointer = Box::into_raw(state);
        if let Err(error) = backing.require_state_address(pointer.cast()) {
            // This Box was just created with the actual compiler allocator;
            // dropping that known Box is safe even when the caller chose wrong.
            unsafe { drop(Box::from_raw(pointer)) };
            return Err(error);
        }
        let observed = match snapshot(unsafe { &*pointer }) {
            Ok(observed) => observed,
            Err(error) => {
                unsafe { drop(Box::from_raw(pointer)) };
                return Err(error);
            }
        };
        STATE.store(pointer, Ordering::Release);
        unsafe { output.write(observed) };
        Ok(())
    })();
    result.map_or_else(|error| -error, |()| 0)
}

/// Observe retained identity/bitmap facts without leasing or reserving.
///
/// # Safety
/// Same ordinary single-thread and output obligations as [`prepare`].
pub unsafe fn observe(backing: Backing, output: *mut MappingFixtureSnapshot, bytes: usize) -> i32 {
    if !output_valid(output, bytes) {
        return -libc::EINVAL;
    }
    let result: Result<(), i32> = (|| {
        let mut action = Action::acquire()?;
        let state = unsafe { current_state(&mut action, backing) }?;
        let observed = snapshot(state)?;
        unsafe { output.write(observed) };
        Ok(())
    })();
    result.map_or_else(|error| -error, |()| 0)
}

/// Lease the actual previously dropped extent, write/read it, then reset it.
///
/// # Safety
/// Same ordinary single-thread and output obligations as [`prepare`]. No
/// allocation lock remains held during this operation's trusted VM syscalls.
pub unsafe fn reuse(backing: Backing, output: *mut MappingFixtureSnapshot, bytes: usize) -> i32 {
    if !output_valid(output, bytes) {
        return -libc::EINVAL;
    }
    let result = (|| {
        let mut action = Action::acquire()?;
        let state = unsafe { current_state(&mut action, backing) }?;
        if !range_is(state.region, state.free_start, state.free_pages, false)? {
            return Err(libc::EIO);
        }
        let lease = state.region.stack(PAGE).map_err(error_number)?;
        if lease.start != state.free_start || lease.pages != state.free_pages {
            return Err(libc::EADDRNOTAVAIL);
        }
        let address = lease.base() as *mut u8;
        for offset in 0..lease.usable_bytes() {
            if unsafe { address.add(offset).read_volatile() } != 0 {
                return Err(libc::EIO);
            }
        }
        unsafe { address.write_volatile(0xa7) };
        if unsafe { address.read_volatile() } != 0xa7 {
            return Err(libc::EIO);
        }
        state.reuse_base = lease.base();
        drop(lease);
        if !range_is(state.region, state.free_start, state.free_pages, false)? {
            return Err(libc::EIO);
        }
        state.reuse_count = state.reuse_count.checked_add(1).ok_or(libc::EOVERFLOW)?;
        let observed = snapshot(state)?;
        unsafe { output.write(observed) };
        Ok(())
    })();
    result.map_or_else(|error| -error, |()| 0)
}

/// Drop only this action's retained spare lease and Tool-allocated state.
///
/// # Safety
/// The caller uses the same ordinary single-thread setup context and performs
/// no further action concurrently. `backing` names the same actual image
/// allocator as at [`prepare`]. No registered runtime stack is released.
pub unsafe fn finish(backing: Backing) -> i32 {
    let result = (|| {
        let mut action = Action::acquire()?;
        let state = unsafe { current_state(&mut action, backing) }?;
        let region = state.region;
        let start = state.live.start;
        let pages = state.live.pages;
        let pointer = STATE.swap(core::ptr::null_mut(), Ordering::AcqRel);
        let _allocation = alloc::enter_dispatch();
        unsafe { drop(Box::from_raw(pointer)) };
        if !range_is(region, start, pages, false)? {
            return Err(libc::EIO);
        }
        Ok(())
    })();
    result.map_or_else(|error| -error, |()| 0)
}

#[cfg(test)]
mod tests {
    use super::Backing;
    use crate::guest::alloc;

    #[test]
    fn fixed_fixture_backing_refuses_legacy_state_before_dereference() {
        // These actual BSS bounds need neither a region nor a live allocation.
        // The address is intentionally not a State: a wrong-backing check must
        // return EFAULT without dereferencing it or consulting another heap.
        let (bottom, top) = alloc::legacy_tool_heap_bounds();
        let address = bottom as *const u8;
        assert_eq!(Backing::Legacy.require_state_address(address), Ok(()));
        assert_eq!(
            Backing::Fixed.require_state_address(address),
            Err(libc::EFAULT)
        );
        assert_eq!(
            Backing::Legacy.require_state_address(top as *const u8),
            Err(libc::EFAULT)
        );
        assert_eq!(
            Backing::Legacy.require_state_address(core::ptr::null()),
            Err(libc::EFAULT)
        );
        assert_eq!(
            Backing::Fixed.require_state_address(core::ptr::null()),
            Err(libc::EFAULT)
        );
    }
}
