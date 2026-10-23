// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the root LICENSE file.

//! Internal DBT instruction observations. These are not a continuous clock,
//! PMU capability, scheduler input, or a replacement for `Guest::read_clock`.

use std::sync::OnceLock;

/// Native ABI-12 record. The owner words name an existing live table, process
/// slot, image and admitted task. Their only operation is equality within that
/// live execution; they are not addresses, ordered IDs or transferable state.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeBranchFact {
    owner: [u64; 5],
    count: u64,
}

const _: () = assert!(std::mem::size_of::<NativeBranchFact>() == 48);

/// Copies a current observation for the current native callback context.
/// Every non-ready result must clear all output words. No pointer is retained.
pub type BranchFactQuery = unsafe extern "C" fn(usize, *mut NativeBranchFact) -> i32;

static QUERY: OnceLock<BranchFactQuery> = OnceLock::new();

/// Installs the optional native observation transport, without enabling any
/// instrumentation. The launch must opt in before its first guest instruction.
pub fn install_branch_fact_query(query: BranchFactQuery) {
    let _ = QUERY.set(query);
}

/// A per-task count scoped to one image. A new task or exec has a different
/// scope; subtracting samples from different scopes is not defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchFact(NativeBranchFact);

impl BranchFact {
    /// Original application conditional instructions completed in this scope.
    pub fn count(self) -> u64 {
        self.0.count
    }

    /// Whether both observations belong to the same live task and image.
    pub fn same_scope(self, other: Self) -> bool {
        self.0.owner == other.0.owner
    }
}

/// Why an observation cannot be used. None of these values means zero work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchFactUnavailable {
    /// Instrumentation was not enabled before launch.
    Disabled,
    /// The existing native lifecycle admission has not bound this task yet.
    PendingOwner,
    /// Original-instruction provenance or lifetime is unsupported.
    Unsupported,
    /// No authenticated raw or stable application cut is available.
    UnknownCut,
    /// The physical count exhausted its nonwrapping representation.
    Overflow,
    /// An ownership or mechanism invariant failed.
    Invalid,
    /// The native callback returned an unknown status or malformed record.
    InvalidNativeRecord,
}

fn decode(status: i32, value: NativeBranchFact) -> Result<BranchFact, BranchFactUnavailable> {
    if status == 1 {
        // Device zero and image epoch zero can be legitimate. Slots are
        // encoded as index+1; task births come from the checked i32 allocator.
        if value.owner[2] == 0 || value.owner[4] == 0 || value.owner[4] > i32::MAX as u64 {
            return Err(BranchFactUnavailable::InvalidNativeRecord);
        }
        return Ok(BranchFact(value));
    }
    if value != NativeBranchFact::default() {
        return Err(BranchFactUnavailable::InvalidNativeRecord);
    }
    Err(match status {
        0 => BranchFactUnavailable::Disabled,
        2 => BranchFactUnavailable::PendingOwner,
        3 => BranchFactUnavailable::Unsupported,
        4 => BranchFactUnavailable::UnknownCut,
        5 => BranchFactUnavailable::Overflow,
        6 => BranchFactUnavailable::Invalid,
        _ => BranchFactUnavailable::InvalidNativeRecord,
    })
}

pub(crate) fn query(context: usize) -> Result<BranchFact, BranchFactUnavailable> {
    let Some(query) = QUERY.get() else {
        return Err(BranchFactUnavailable::Disabled);
    };
    let mut value = NativeBranchFact::default();
    // SAFETY: DbtGuest supplies its live native callback context, and output
    // remains writable for the duration of the synchronous callback.
    let status = unsafe { query(context, &mut value) };
    decode(status, value)
}

// Diagnostic-only standalone prototype observation at the actual concrete
// DbtGuest/Tool bridge. It never enables the native mechanism and is absent
// from the normal external Detcore runtime (no prototype-runtime feature).
#[cfg(feature = "prototype-runtime")]
pub(crate) fn observe_test_bridge<T: reverie::Tool>(
    guest: &crate::DbtGuest<'_, T>,
    event: &str,
    sysnum: i64,
) {
    static ENABLED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        std::env::var_os("HERMIT_DBT_TEST_BRANCH_FACTS").is_some_and(|value| value == "1")
    });
    if !*ENABLED {
        return;
    }
    let mut registers = std::mem::MaybeUninit::<libc::user_regs_struct>::zeroed();
    // SAFETY: the concrete bridge owns the live native context and writable
    // register buffer. No guest state or counter is changed by either query.
    let register_status = unsafe { (guest.read_registers)(guest.context, registers.as_mut_ptr()) };
    let registers = unsafe { registers.assume_init() };
    let first = guest.branch_fact();
    let repeated = guest.branch_fact();
    let (status, owner, count) = match first {
        Ok(fact) => ("Ready".to_owned(), Some(fact.0.owner), Some(fact.count())),
        Err(reason) => (format!("{reason:?}"), None, None),
    };
    let observation = serde_json::json!({
        "event": event, "sysnum": sysnum,
        "pid": guest.pid.as_raw(), "tid": guest.tid.as_raw(),
        "status": status, "owner": owner, "count": count,
        "repeated_equal": first == repeated, "register_status": register_status,
        "registers": [registers.r15, registers.r14, registers.r13, registers.r12,
            registers.rbp, registers.rbx, registers.r11, registers.r10, registers.r9,
            registers.r8, registers.rax, registers.rcx, registers.rdx, registers.rsi,
            registers.rdi, registers.orig_rax, registers.rip, registers.cs,
            registers.eflags, registers.rsp, registers.ss, registers.fs_base,
            registers.gs_base, registers.ds, registers.es, registers.fs, registers.gs],
    });
    crate::tools::emit_line(&format!("BRANCH_FACT_OBSERVATION {observation}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonready_is_never_an_observed_zero() {
        for status in [0, 2, 3, 4, 5, 6, -1, i32::MAX] {
            assert!(decode(status, NativeBranchFact::default()).is_err());
            let dirty = NativeBranchFact {
                count: 1,
                ..NativeBranchFact::default()
            };
            assert_eq!(
                decode(status, dirty),
                Err(BranchFactUnavailable::InvalidNativeRecord)
            );
        }
        for owner in [[1, 2, 0, 0, 1], [1, 2, 1, 0, 0], [1, 2, 1, 0, u64::MAX]] {
            assert_eq!(
                decode(1, NativeBranchFact { owner, count: 0 }),
                Err(BranchFactUnavailable::InvalidNativeRecord)
            );
        }
    }

    #[test]
    fn counts_retain_exact_values_and_each_lifetime_word() {
        let native = NativeBranchFact {
            owner: [0, 2, 3, 0, 5],
            count: 0,
        };
        let first = decode(1, native).unwrap();
        let later = decode(
            1,
            NativeBranchFact {
                count: u64::MAX,
                ..native
            },
        )
        .unwrap();
        assert_eq!(first.count(), 0);
        assert_eq!(later.count(), u64::MAX);
        assert!(first.same_scope(later));
        for word in 0..5 {
            let mut changed = native;
            changed.owner[word] += 1;
            assert!(!first.same_scope(decode(1, changed).unwrap()));
        }
    }
}
