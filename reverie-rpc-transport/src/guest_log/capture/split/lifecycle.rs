//! Plain shared state prepared before clone; all process-local wrappers are later.
use std::io;
use std::ptr::NonNull;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

const VERSION: u64 = 1;
const CLOSED: u64 = 1 << 63;

#[repr(C, align(64))]
struct Header {
    version: AtomicU64,
    phase: AtomicU64,
    admission: AtomicU64,
    late: AtomicU64,
    fault: AtomicU64,
    disposition: AtomicU64,
    guest_success: AtomicU64,
    rpc_issues: AtomicU64,
}

pub(in crate::guest_log::capture) struct Lifecycle(NonNull<Header>);
// Only atomic, immutable-layout shared storage crosses process/thread boundaries.
unsafe impl Send for Lifecycle {}
unsafe impl Sync for Lifecycle {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleSnapshot {
    pub version_valid: bool,
    pub started: bool,
    pub finished: bool,
    pub closed: bool,
    pub entrants: u64,
    pub late_writes: u64,
    pub faulted: bool,
    pub disposition: u64,
    pub guest_success: bool,
    pub rpc_issues: u64,
}
impl LifecycleSnapshot {
    pub(super) fn integrity_ready(self) -> bool {
        self.version_valid
            && self.started
            && self.finished
            && self.closed
            && self.entrants == 0
            && self.late_writes == 0
            && !self.faulted
            && self.disposition == 1
            && self.rpc_issues == 0
    }

    pub(super) fn qualifies(self) -> bool {
        self.version_valid
            && self.started
            && self.finished
            && self.closed
            && self.entrants == 0
            && self.late_writes == 0
            && !self.faulted
            && self.disposition == 1
            && self.guest_success
            && self.rpc_issues == 0
    }
}
impl Lifecycle {
    pub(super) fn new() -> io::Result<Self> {
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<Header>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let pointer = NonNull::new(pointer.cast::<Header>()).expect("mmap nonnull");
        unsafe {
            pointer.as_ptr().write(Header {
                version: AtomicU64::new(VERSION),
                phase: AtomicU64::new(0),
                admission: AtomicU64::new(0),
                late: AtomicU64::new(0),
                fault: AtomicU64::new(0),
                disposition: AtomicU64::new(0),
                guest_success: AtomicU64::new(0),
                rpc_issues: AtomicU64::new(u64::MAX),
            });
        }
        Ok(Self(pointer))
    }
    fn header(&self) -> &Header {
        unsafe { self.0.as_ref() }
    }
    pub(super) fn fault(&self) {
        self.header().fault.store(1, Ordering::Release);
    }
    pub(super) fn start(&self) -> bool {
        let h = self.header();
        if h.version.load(Ordering::Acquire) != VERSION
            || h.phase
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            self.fault();
            false
        } else {
            true
        }
    }
    pub(super) fn enter(&self) -> bool {
        let h = self.header();
        if h.admission
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                v.checked_add(1)
                    .filter(|_| v & CLOSED == 0 && v < CLOSED - 1)
            })
            .is_err()
        {
            if h.late
                .try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
                .is_err()
            {
                self.fault();
            }
            self.fault();
            return false;
        }
        true
    }
    pub(super) fn leave(&self) {
        self.header().admission.fetch_sub(1, Ordering::Release);
    }
    pub(super) fn close(&self) {
        self.header().admission.fetch_or(CLOSED, Ordering::AcqRel);
    }
    pub(super) fn facts(&self, disposition: u64, guest_success: bool, rpc_issues: u64) {
        let h = self.header();
        if h.disposition
            .compare_exchange(0, disposition, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.fault();
        }
        h.guest_success
            .store(u64::from(guest_success), Ordering::Release);
        h.rpc_issues.store(rpc_issues, Ordering::Release);
    }
    pub(super) fn finish(&self) {
        if self
            .header()
            .phase
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.fault();
        }
    }
    pub(in crate::guest_log::capture) fn snapshot(&self) -> LifecycleSnapshot {
        let h = self.header();
        let admission = h.admission.load(Ordering::Acquire);
        let phase = h.phase.load(Ordering::Acquire);
        LifecycleSnapshot {
            version_valid: h.version.load(Ordering::Acquire) == VERSION,
            started: matches!(phase, 1 | 2),
            finished: phase == 2,
            closed: admission & CLOSED != 0,
            entrants: admission & !CLOSED,
            late_writes: h.late.load(Ordering::Acquire),
            faulted: h.fault.load(Ordering::Acquire) != 0,
            disposition: h.disposition.load(Ordering::Acquire),
            guest_success: h.guest_success.load(Ordering::Acquire) == 1,
            rpc_issues: h.rpc_issues.load(Ordering::Acquire),
        }
    }
}
impl Drop for Lifecycle {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.0.as_ptr().cast(), std::mem::size_of::<Header>());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_shared_version_overflow_and_unknown_disposition_refuse() {
        let life = Lifecycle::new().unwrap();
        life.header().version.store(9, Ordering::Release);
        assert!(!life.start());
        assert!(life.snapshot().faulted && !life.snapshot().version_valid);
        let life = Lifecycle::new().unwrap();
        assert!(life.start());
        life.header().admission.store(CLOSED - 1, Ordering::Release);
        assert!(!life.enter());
        assert_eq!(life.snapshot().entrants, CLOSED - 1);
        assert!(life.snapshot().faulted);
        let life = Lifecycle::new().unwrap();
        assert!(life.start());
        life.facts(99, true, 0);
        life.close();
        life.finish();
        assert!(!life.snapshot().qualifies());
        let life = Lifecycle::new().unwrap();
        assert!(life.start());
        life.facts(1, true, 0);
        life.facts(1, true, 0);
        life.close();
        life.finish();
        assert!(life.snapshot().faulted && !life.snapshot().qualifies());
    }
}
