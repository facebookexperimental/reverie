//! Literal M2 observations shared by standalone and genuine Detcore consumers.
//! Runtime/package qualification and successful child exit remain caller duties.
//! This comparator never converts an absent callback into a placement pass.

use std::path::Path;

use serde::Deserialize;

pub const REGION_BASE: u64 = 0x6000_0000_0000;
pub const REGION_END: u64 = 0x6001_0000_0000;
pub const CONTROL_BYTES: u64 = 1024 * 1024;
pub const PAGE_BYTES: u64 = 4096;
pub const CALLBACK_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub abi_version: u64,
    pub status: u64,
    pub current_tid: u64,
    pub alt_result: i64,
    pub alt_sp: u64,
    pub alt_size: u64,
    pub alt_flags: u64,
    pub continuation_prepared: u64,
    pub continuation_bottom: u64,
    pub continuation_top: u64,
    pub continuation_owner_tid: u64,
    pub marker_number: u64,
    pub marker_guest_ip: u64,
    pub marker_arm_tid: u64,
    pub marker_armed: u64,
    pub marker_hits: u64,
    pub reached_rsp: u64,
    pub reached_tid: u64,
    pub reached_guest_ip: u64,
    pub owned_entries: u64,
    pub owned_callbacks: u64,
    pub owned_completions: u64,
    pub alt_probe_mask: u64,
    pub alt_read_result: i64,
    pub alt_lower_result: i64,
    pub alt_upper_result: i64,
    pub continuation_probe_mask: u64,
    pub continuation_read_result: i64,
    pub continuation_lower_result: i64,
    pub continuation_upper_result: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: u64,
    pub mode: String,
    pub owner: String,
    pub marker_ip: u64,
    pub marker_result: i64,
    pub before_result: i32,
    pub arm_result: i32,
    pub after_result: i32,
    pub marker_bytes_before: [u8; 2],
    pub marker_bytes_after: [u8; 2],
    pub region_probe_executed: u64,
    pub region_probe_result: i64,
    pub before: Query,
    pub after: Query,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Continuation {
    /// Current standalone Strace/Compat/built-in path, not a callback-stack pass.
    Absent,
    /// Caller must qualify the genuine Detcore leaf; custom Tools are additional.
    Reached,
}

fn demand(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

pub fn parse(bytes: &[u8]) -> Result<Observation, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("complete M2 observation JSON: {error}"))
}

fn no_marker(query: &Query) -> bool {
    query.marker_number == 0
        && query.marker_guest_ip == 0
        && query.marker_arm_tid == 0
        && query.marker_armed == 0
        && query.marker_hits == 0
        && query.reached_rsp == 0
        && query.reached_tid == 0
        && query.reached_guest_ip == 0
}

fn no_continuation(query: &Query) -> bool {
    query.continuation_prepared == 0
        && query.continuation_bottom == 0
        && query.continuation_top == 0
        && query.continuation_owner_tid == 0
        && query.owned_entries == 0
        && query.owned_callbacks == 0
        && query.owned_completions == 0
        && query.continuation_probe_mask == 0
        && query.continuation_read_result == 0
        && query.continuation_lower_result == 0
        && query.continuation_upper_result == 0
}

fn one_increment(before: u64, after: u64) -> bool {
    before.checked_add(1) == Some(after)
}

/// Require successful real observations before any fixed-placement assertion.
pub fn verify_observation(
    observation: &Observation,
    owner: &Path,
    mode: &str,
    alt_stack: bool,
    continuation: Continuation,
) -> Result<(), String> {
    demand(
        observation.schema == 1
            && observation.mode == mode
            && owner.to_str() == Some(observation.owner.as_str()),
        "M2 schema/mode/exact qualified owner differs",
    )?;
    demand(
        observation.before_result == 0
            && observation.arm_result == 0
            && observation.after_result == 0
            && observation.marker_ip != 0
            && observation.marker_ip % 64 == 60
            && observation.marker_result == 0
            && observation.marker_bytes_before == [0x0f, 0x05]
            && observation.marker_bytes_after == [0x0f, 0x05],
        "M2 query/arm/actual literal marker did not complete successfully",
    )?;
    let before = &observation.before;
    let after = &observation.after;
    for query in [before, after] {
        demand(
            query.abi_version == 1
                && query.status == 0
                && query.alt_result == 0
                && query.current_tid != 0,
            "M2 query ABI/kernel registration/raw TID failed",
        )?;
    }
    demand(
        before.current_tid == after.current_tid
            && before.alt_sp == after.alt_sp
            && before.alt_size == after.alt_size
            && before.alt_flags == after.alt_flags
            && before.continuation_prepared == after.continuation_prepared
            && before.continuation_bottom == after.continuation_bottom
            && before.continuation_top == after.continuation_top
            && before.continuation_owner_tid == after.continuation_owner_tid,
        "M2 query or marker changed actual registration/prepared descriptor/TID",
    )?;
    demand(
        no_marker(before),
        "M2 new child observer was already armed/reached",
    )?;
    demand(
        after.marker_number == libc::SYS_write as u64
            && after.marker_guest_ip == observation.marker_ip
            && after.marker_arm_tid == after.current_tid
            && after.marker_armed == 1,
        "M2 marker arm differs from this thread and exact syscall instruction",
    )?;
    let expected_alt_size =
        (libc::SIGSTKSZ as u64).max(64 * 1024).div_ceil(PAGE_BYTES) * PAGE_BYTES;
    for query in [before, after] {
        if alt_stack {
            demand(
                query.alt_flags == 0
                    && query.alt_sp != 0
                    && query.alt_size == expected_alt_size
                    && query.alt_probe_mask == 7
                    && query.alt_read_result == 1,
                "M2 actual enabled altstack/capacity/interior read control absent",
            )?;
            demand(
                [query.alt_lower_result, query.alt_upper_result]
                    .into_iter()
                    .all(|result| result == 1 || result == -i64::from(libc::EFAULT)),
                "M2 boundary read failed independently of mapping accessibility",
            )?;
        } else {
            demand(
                query.alt_flags == libc::SS_DISABLE as u64
                    && query.alt_sp == 0
                    && query.alt_size == 0
                    && query.alt_probe_mask == 0
                    && query.alt_read_result == 0
                    && query.alt_lower_result == 0
                    && query.alt_upper_result == 0,
                "M2 clean-exec ALT_STACK=0/inert path changed or received probe credit",
            )?;
        }
    }
    match continuation {
        Continuation::Absent => demand(
            no_continuation(before)
                && no_continuation(after)
                && after.marker_hits == 0
                && after.reached_rsp == 0
                && after.reached_tid == 0
                && after.reached_guest_ip == 0,
            "M2 standalone NotPrepared/NotReached state was changed or relabelled",
        )?,
        Continuation::Reached => {
            for query in [before, after] {
                demand(
                    query.continuation_prepared == 1
                        && query.continuation_bottom != 0
                        && query
                            .continuation_top
                            .checked_sub(query.continuation_bottom)
                            == Some(CALLBACK_BYTES)
                        && query.continuation_owner_tid == query.current_tid
                        && query.continuation_probe_mask == 7
                        && query.continuation_read_result == 1
                        && query.continuation_lower_result == -i64::from(libc::EFAULT)
                        && query.continuation_upper_result == -i64::from(libc::EFAULT),
                    "M2 prepared 8 MiB continuation/current owner/actual guards absent",
                )?;
            }
            demand(
                after.marker_hits == 1
                    && after.reached_tid == after.current_tid
                    && after.reached_guest_ip == observation.marker_ip
                    && (after.continuation_bottom..after.continuation_top)
                        .contains(&after.reached_rsp)
                    && one_increment(before.owned_entries, after.owned_entries)
                    && one_increment(before.owned_callbacks, after.owned_callbacks)
                    && one_increment(before.owned_completions, after.owned_completions),
                "M2 exact marker did not reach and return from this actual owned callback",
            )?;
        }
    }
    if mode == "inert" {
        demand(
            !alt_stack
                && continuation == Continuation::Absent
                && observation.region_probe_executed == 1
                && observation.region_probe_result == -i64::from(libc::ENOMEM),
            "M2 inert true leaf reserved the fixed range or altered stack state",
        )?;
    } else {
        demand(
            mode == "observe"
                && observation.region_probe_executed == 0
                && observation.region_probe_result == 0,
            "M2 unexpected or relabelled fixed-range probe",
        )?;
    }
    Ok(())
}

fn guarded_range(bottom: u64, bytes: u64) -> Result<(u64, u64), String> {
    let lower = bottom.checked_sub(PAGE_BYTES);
    let top = bottom.checked_add(bytes);
    let upper_end = top.and_then(|top| top.checked_add(PAGE_BYTES));
    demand(
        bottom & (PAGE_BYTES - 1) == 0
            && bytes != 0
            && bytes & (PAGE_BYTES - 1) == 0
            && lower.is_some_and(|lower| lower >= REGION_BASE + CONTROL_BYTES)
            && upper_end.is_some_and(|end| end <= REGION_END - PAGE_BYTES),
        "M2 actual guarded stack is outside the literal fixed allocation extent",
    )?;
    Ok((lower.unwrap(), upper_end.unwrap()))
}

/// Fixed region + real denied guard reads. Unprepared paths get no callback credit.
/// Actual guard SIGSEGV and reserved geometry are separate allocator controls.
pub fn verify_fixed_stack_placement(
    observation: &Observation,
    alt_stack: bool,
    continuation: Continuation,
) -> Result<(), String> {
    let query = &observation.after;
    let alt_range = if alt_stack {
        let range = guarded_range(query.alt_sp, query.alt_size)?;
        demand(
            query.alt_probe_mask == 7
                && query.alt_read_result == 1
                && query.alt_lower_result == -i64::from(libc::EFAULT)
                && query.alt_upper_result == -i64::from(libc::EFAULT),
            "M2 registered altstack has no actual denied lower/upper guard reads",
        )?;
        Some(range)
    } else {
        None
    };
    if continuation == Continuation::Reached {
        demand(
            query.continuation_prepared == 1
                && query.marker_hits == 1
                && query.reached_tid == query.current_tid
                && (query.continuation_bottom..query.continuation_top).contains(&query.reached_rsp)
                && query.continuation_probe_mask == 7
                && query.continuation_read_result == 1
                && query.continuation_lower_result == -i64::from(libc::EFAULT)
                && query.continuation_upper_result == -i64::from(libc::EFAULT),
            "M2 missing genuine reached callback cannot satisfy fixed stack placement",
        )?;
        demand(
            query
                .continuation_top
                .checked_sub(query.continuation_bottom)
                == Some(CALLBACK_BYTES),
            "M2 callback capacity differs from the exact 8 MiB contract",
        )?;
        let callback = guarded_range(query.continuation_bottom, CALLBACK_BYTES)?;
        if let Some(alt) = alt_range {
            demand(
                alt.1 <= callback.0 || callback.1 <= alt.0,
                "M2 published altstack and continuation leases overlap",
            )?;
        }
    }
    demand(
        alt_stack || continuation == Continuation::Reached,
        "M2 path with neither owned stack has no fixed-placement credit",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic comparator controls only; never executed-placement evidence.
    fn synthetic_observation() -> Observation {
        let before = Query {
            abi_version: 1,
            current_tid: 42,
            alt_sp: REGION_BASE + CONTROL_BYTES + PAGE_BYTES,
            alt_size: 64 * 1024,
            continuation_prepared: 1,
            continuation_bottom: REGION_BASE + 2 * CONTROL_BYTES + PAGE_BYTES,
            continuation_top: REGION_BASE + 2 * CONTROL_BYTES + PAGE_BYTES + CALLBACK_BYTES,
            continuation_owner_tid: 42,
            owned_entries: 3,
            owned_callbacks: 3,
            owned_completions: 3,
            alt_probe_mask: 7,
            alt_read_result: 1,
            alt_lower_result: -i64::from(libc::EFAULT),
            alt_upper_result: -i64::from(libc::EFAULT),
            continuation_probe_mask: 7,
            continuation_read_result: 1,
            continuation_lower_result: -i64::from(libc::EFAULT),
            continuation_upper_result: -i64::from(libc::EFAULT),
            ..Query::default()
        };
        let after = Query {
            marker_number: libc::SYS_write as u64,
            marker_guest_ip: 0x40123c,
            marker_arm_tid: 42,
            marker_armed: 1,
            marker_hits: 1,
            reached_rsp: before.continuation_top - 256,
            reached_tid: 42,
            reached_guest_ip: 0x40123c,
            owned_entries: 4,
            owned_callbacks: 4,
            owned_completions: 4,
            ..before.clone()
        };
        Observation {
            schema: 1,
            mode: "observe".into(),
            owner: "/known/libdetcore_liteinst.so".into(),
            marker_ip: 0x40123c,
            marker_result: 0,
            before_result: 0,
            arm_result: 0,
            after_result: 0,
            marker_bytes_before: [0x0f, 0x05],
            marker_bytes_after: [0x0f, 0x05],
            region_probe_executed: 0,
            region_probe_result: 0,
            before,
            after,
        }
    }

    #[test]
    fn rejects_foreign_and_unreached_callback_records() {
        let valid = synthetic_observation();
        let verify = |observation: &Observation| {
            verify_observation(
                observation,
                Path::new("/known/libdetcore_liteinst.so"),
                "observe",
                true,
                Continuation::Reached,
            )
        };
        assert!(
            verify(&valid).is_ok(),
            "synthetic positive comparator control"
        );
        for mutation in 0..9 {
            let mut changed = valid.clone();
            match mutation {
                0 => changed.after.marker_hits = 0,
                1 => changed.after.reached_rsp = 0x7fff_0000_0000,
                2 => changed.after.reached_tid = 43,
                3 => changed.after.marker_arm_tid = 43,
                4 => changed.after.owned_completions -= 1,
                5 => changed.owner = "/other/libdetcore_liteinst.so".into(),
                6 => changed.marker_result = 1,
                7 => changed.marker_result = -i64::from(libc::EOPNOTSUPP),
                8 => {
                    changed.marker_ip += 1;
                    changed.after.marker_guest_ip += 1;
                    changed.after.reached_guest_ip += 1;
                }
                _ => unreachable!(),
            }
            assert!(verify(&changed).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn rejects_unprobed_and_readable_guards() {
        let valid = synthetic_observation();
        let verify = |observation: &Observation| {
            verify_fixed_stack_placement(observation, true, Continuation::Reached)
        };
        assert!(
            verify(&valid).is_ok(),
            "synthetic positive comparator control"
        );
        for mutation in 0..6 {
            let mut changed = valid.clone();
            match mutation {
                0 => changed.after.alt_probe_mask = 0,
                1 => changed.after.alt_read_result = -i64::from(libc::EPERM),
                2 => changed.after.alt_lower_result = 1,
                3 => changed.after.continuation_upper_result = 1,
                4 => changed.after.alt_sp = REGION_BASE + PAGE_BYTES,
                5 => changed.after.continuation_bottom = 0x7fff_0000_0000,
                _ => unreachable!(),
            }
            assert!(verify(&changed).is_err(), "mutation {mutation}");
        }
    }
}
