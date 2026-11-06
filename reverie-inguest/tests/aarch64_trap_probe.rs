/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Kernel-semantics contract for the aarch64 trap runtime, measured by the
//! maintained C probe in `tests/fixtures/aarch64_trap_probe.c`.
//!
//! The aarch64 seccomp/SIGSYS runtime is written against kernel-visible
//! facts that no x86-64 host can check: which instruction pointer the
//! seccomp filter sees for an `svc`, how `si_call_addr` relates to the
//! ucontext `pc`, whether syscall arguments survive into the frame, where
//! a private restorer's `rt_sigreturn` is reported, which BTI landing pads
//! gate entries need, what the SVE signal-record chain looks like, and the
//! host page size (targeted hosts run both 4 KiB and 64 KiB pages).
//!
//! On aarch64, the test at the bottom of this file builds the probe with
//! `cc`, runs it, and asserts on its parsed `KEY=VALUE` measurements with
//! exact typed comparisons. On every other architecture only the parser
//! unit tests run; the probe execution is staged, not counted as coverage.
//! The crate's architecture gate still refuses aarch64 builds, so today
//! the probe executes only by building the C fixture directly on aarch64
//! hardware (see its header). Widening that gate must make
//! `cargo test --test aarch64_trap_probe` execute the real test below on
//! aarch64; until then its constants enter as hardware-measured claims
//! whose host-side consequences are pinned by the seccomp evaluator tests.
//!
//! Regression pinned by name: the probe's P1 verdict strings derive from a
//! pid cached *before* the discriminating filter installs (comparing
//! against a `getpid()` issued under the filter inverts MATCH/NO), and
//! this test asserts `SITE=NO` / `SITE_PLUS4=MATCH` from the raw returns.
//!
//! Syscall user dispatch is capability-dependent (targeted kernels may be
//! built without it): the test accepts either a measured trap or an
//! explicit enable failure, and fails on anything else.

use std::collections::BTreeMap;

/// One parsed probe run: measurement key to its exact value token.
///
/// Scalar fixture rows are exactly `KEY=VALUE` with nothing after the
/// value: any trailing field rejects the whole run (a second measurement
/// hidden after a space or tab must not be silently discarded). Only the
/// fixture's named diagnostic rows may carry a suffix, each parsed and
/// discarded only in its exact form: `P1_IP_CANDIDATE_*` rows end with
/// ` (ret=<i64>)`, `P6_*` case rows end with ` ret=<i64>` or
/// ` errno=<i64>`. Lines whose key contains whitespace (`RESULT ...`
/// summaries, `== TEST ==` banners) are not measurements and are skipped
/// here; `RESULT` lines are parsed by [`result_exit`].
struct Measurements<'a> {
    values: BTreeMap<&'a str, &'a str>,
}

fn measurement_value<'a>(key: &str, rest: &'a str, line: &str) -> Result<&'a str, String> {
    fn check_token(key: &str, value: &str, line: &str) -> Result<(), String> {
        if value.is_empty() || value.contains([' ', '\t', '=']) {
            return Err(format!(
                "malformed measurement value for {key:?} in {line:?}"
            ));
        }
        Ok(())
    }
    if key.starts_with("P1_IP_CANDIDATE_") {
        if let Some((value, suffix)) = rest.split_once(" (ret=") {
            let digits = suffix
                .strip_suffix(')')
                .ok_or_else(|| format!("malformed ret suffix for {key:?} in {line:?}"))?;
            digits
                .parse::<i64>()
                .map_err(|_| format!("malformed ret suffix for {key:?} in {line:?}"))?;
            check_token(key, value, line)?;
            return Ok(value);
        }
    }
    if key.starts_with("P6_") {
        for marker in [" ret=", " errno="] {
            if let Some((value, suffix)) = rest.split_once(marker) {
                suffix
                    .parse::<i64>()
                    .map_err(|_| format!("malformed suffix for {key:?} in {line:?}"))?;
                check_token(key, value, line)?;
                return Ok(value);
            }
        }
    }
    if rest.is_empty() || rest.contains([' ', '\t']) {
        return Err(format!(
            "measurement {key:?} has trailing fields in {line:?}"
        ));
    }
    Ok(rest)
}

fn parse_measurements(out: &str) -> Result<Measurements<'_>, String> {
    let mut values = BTreeMap::new();
    for line in out.lines() {
        let Some((key, rest)) = line.split_once('=') else {
            continue;
        };
        if key.is_empty() || key.contains(char::is_whitespace) {
            continue;
        }
        let value = measurement_value(key, rest, line)?;
        if values.insert(key, value).is_some() {
            return Err(format!("duplicate measurement key {key:?}"));
        }
    }
    Ok(Measurements { values })
}

impl Measurements<'_> {
    fn get(&self, key: &str) -> Result<&str, String> {
        self.values
            .get(key)
            .copied()
            .ok_or_else(|| format!("missing measurement {key:?}"))
    }

    fn check_str(&self, key: &str, expected: &str) -> Result<(), String> {
        let actual = self.get(key)?;
        if actual == expected {
            Ok(())
        } else {
            Err(format!("{key}={actual:?}, want {expected:?}"))
        }
    }

    fn check_i64(&self, key: &str, expected: i64) -> Result<(), String> {
        let raw = self.get(key)?;
        let actual = raw
            .parse::<i64>()
            .map_err(|_| format!("{key}={raw:?} does not parse as an integer"))?;
        if actual == expected {
            Ok(())
        } else {
            Err(format!("{key}={actual}, want {expected} (raw {raw:?})"))
        }
    }

    fn check_hex(&self, key: &str, expected: u64) -> Result<(), String> {
        let raw = self.get(key)?;
        let digits = raw
            .strip_prefix("0x")
            .ok_or_else(|| format!("{key}={raw:?} is not 0x-prefixed hex"))?;
        let value = u64::from_str_radix(digits, 16)
            .map_err(|_| format!("{key}={raw:?} does not parse as hex"))?;
        if value == expected {
            Ok(())
        } else {
            Err(format!("{key}={raw:?}, want {expected:#x}"))
        }
    }

    fn contains(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }
}

/// The single `RESULT <name> STATUS=...` terminal record for one child.
///
/// Exactly one record may exist for `name` — a second, even identical,
/// rejects the run, so a later failure record can never hide behind an
/// earlier success. Within the record every field is unique and the field
/// set must match the status: `EXITED` carries only `CODE`, `SIGNALED`
/// only `SIG`, `FORK_FAIL`/`WAIT_FAIL` only `ERRNO`, `OTHER` only `RAW`.
/// Conflicting or duplicate fields reject rather than overwrite.
fn result_exit(out: &str, name: &str) -> Result<(String, Option<i64>), String> {
    fn set_once<T>(slot: &mut Option<T>, value: T, what: &str, line: &str) -> Result<(), String> {
        if slot.replace(value).is_some() {
            return Err(format!("duplicate {what} field in {line:?}"));
        }
        Ok(())
    }
    fn field_i64(value: &str, what: &str, line: &str) -> Result<i64, String> {
        value
            .parse::<i64>()
            .map_err(|_| format!("unparsable {what} in {line:?}"))
    }
    let prefix = format!("RESULT {name} ");
    let mut records = out.lines().filter(|line| line.starts_with(&prefix));
    let line = records
        .next()
        .ok_or_else(|| format!("missing RESULT line for {name:?}"))?;
    if records.next().is_some() {
        return Err(format!("duplicate RESULT lines for {name:?}"));
    }
    let mut status: Option<String> = None;
    let mut code: Option<i64> = None;
    let mut sig: Option<i64> = None;
    let mut errno_value: Option<i64> = None;
    let mut raw: Option<String> = None;
    for field in line[prefix.len()..].split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            return Err(format!("malformed RESULT field {field:?} in {line:?}"));
        };
        match key {
            "STATUS" => set_once(&mut status, value.to_string(), key, line)?,
            "CODE" => set_once(&mut code, field_i64(value, key, line)?, key, line)?,
            "SIG" => set_once(&mut sig, field_i64(value, key, line)?, key, line)?,
            "ERRNO" => set_once(&mut errno_value, field_i64(value, key, line)?, key, line)?,
            "RAW" => set_once(&mut raw, value.to_string(), key, line)?,
            _ => return Err(format!("unknown RESULT field {key:?} in {line:?}")),
        }
    }
    let status = status.ok_or_else(|| format!("RESULT {name}: no STATUS field in {line:?}"))?;
    let consistent = match status.as_str() {
        "EXITED" => code.is_some() && sig.is_none() && errno_value.is_none() && raw.is_none(),
        "SIGNALED" => sig.is_some() && code.is_none() && errno_value.is_none() && raw.is_none(),
        "FORK_FAIL" | "WAIT_FAIL" => {
            errno_value.is_some() && code.is_none() && sig.is_none() && raw.is_none()
        }
        "OTHER" => raw.is_some() && code.is_none() && sig.is_none() && errno_value.is_none(),
        _ => false,
    };
    if !consistent {
        return Err(format!(
            "RESULT {name}: fields inconsistent with STATUS={status} in {line:?}"
        ));
    }
    Ok((status, code))
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    #[test]
    fn exact_values_reject_numeric_prefix_extensions() {
        // Near-miss controls: a prefix predicate accepted both of these.
        let plus40 = parse_measurements("P1_CALL_MINUS_SITE=+40\n").unwrap();
        assert!(plus40.check_i64("P1_CALL_MINUS_SITE", 4).is_err());
        let thousand = parse_measurements("P5_ENTRIES=1000\n").unwrap();
        assert!(thousand.check_i64("P5_ENTRIES", 100).is_err());
        let exact = parse_measurements("P1_CALL_MINUS_SITE=+4\nP5_ENTRIES=100\n").unwrap();
        exact.check_i64("P1_CALL_MINUS_SITE", 4).unwrap();
        exact.check_i64("P5_ENTRIES", 100).unwrap();
    }

    #[test]
    fn delimited_diagnostic_suffix_is_not_part_of_the_value() {
        let m =
            parse_measurements("P1_IP_CANDIDATE_SITE=NO (ret=-273)\nP6_BTI_C_BLR=OK ret=1234\n")
                .unwrap();
        m.check_str("P1_IP_CANDIDATE_SITE", "NO").unwrap();
        m.check_str("P6_BTI_C_BLR", "OK").unwrap();
        assert!(m.check_str("P1_IP_CANDIDATE_SITE", "N").is_err());
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        assert!(parse_measurements("P3_RESUME_OK=1\nP3_RESUME_OK=0\n").is_err());
        assert!(parse_measurements("P3_RESUME_OK=1\nP3_RESUME_OK=1\n").is_err());
    }

    #[test]
    fn result_lines_parse_status_and_code_exactly() {
        let out = "RESULT P4 STATUS=EXITED CODE=0\nRESULT P6 STATUS=SIGNALED SIG=4\n";
        assert_eq!(
            result_exit(out, "P4").unwrap(),
            ("EXITED".to_string(), Some(0))
        );
        assert_eq!(result_exit(out, "P6").unwrap().0, "SIGNALED");
        assert!(result_exit(out, "MISSING").is_err());
    }

    // Witnessed malformed shapes (delta review): none of these may be
    // normalized into an accepted measurement or terminal record.
    #[test]
    fn scalar_must_not_accept_numeric_suffix() {
        let raw = "P1_CALL_MINUS_SITE=+4 0\n";
        let got = parse_measurements(raw).and_then(|m| m.check_i64("P1_CALL_MINUS_SITE", 4));
        assert!(got.is_err(), "malformed row accepted: {raw:?}");
    }

    #[test]
    fn scalar_must_not_hide_duplicate_after_space() {
        let raw = "P3_RESUME_OK=1 P3_RESUME_OK=0\n";
        let got = parse_measurements(raw).and_then(|m| m.check_i64("P3_RESUME_OK", 1));
        assert!(got.is_err(), "conflicting record hidden: {raw:?}");
    }

    #[test]
    fn scalar_must_not_hide_duplicate_after_tab() {
        let raw = "P3_RESUME_OK=1\tP3_RESUME_OK=0\n";
        let got = parse_measurements(raw).and_then(|m| m.check_i64("P3_RESUME_OK", 1));
        assert!(got.is_err(), "conflicting record hidden: {raw:?}");
    }

    #[test]
    fn result_must_not_replace_signaled_with_exited() {
        let raw = "RESULT P4 STATUS=SIGNALED SIG=4 STATUS=EXITED CODE=0\n";
        assert!(
            result_exit(raw, "P4").is_err(),
            "conflicting status: {raw:?}"
        );
    }

    #[test]
    fn result_must_not_replace_nonzero_code() {
        let raw = "RESULT P4 STATUS=EXITED CODE=7 CODE=0\n";
        assert!(result_exit(raw, "P4").is_err(), "conflicting code: {raw:?}");
    }

    #[test]
    fn result_must_not_hide_later_failed_terminal_record() {
        let raw = "RESULT P4 STATUS=EXITED CODE=0\nRESULT P4 STATUS=WAIT_FAIL ERRNO=10\n";
        assert!(
            result_exit(raw, "P4").is_err(),
            "later record hidden: {raw:?}"
        );
    }

    #[test]
    fn result_must_reject_duplicate_identical_terminal_records() {
        let raw = "RESULT P4 STATUS=EXITED CODE=0\nRESULT P4 STATUS=EXITED CODE=0\n";
        assert!(result_exit(raw, "P4").is_err(), "duplicate record: {raw:?}");
    }
}

#[cfg(target_arch = "aarch64")]
#[path = "../../reverie-rpc-transport/tests/fixtures/owned_lifecycle.rs"]
mod owned_lifecycle;

#[cfg(target_arch = "aarch64")]
mod probe {
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use super::owned_lifecycle;
    use super::parse_measurements;
    use super::result_exit;

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl Fixture {
        fn build() -> Self {
            static SERIAL: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "reverie-aarch64-trap-probe-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let fixture = Self(directory);
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let mut command = Command::new("cc");
            command.args(["-O1", "-g", "-Wall", "-o"]);
            command.arg(fixture.0.join("probe"));
            command.arg(manifest.join("tests/fixtures/aarch64_trap_probe.c"));
            command.arg("-pthread");
            println!("actual fixture compile: {command:?}");
            let (output, _) = owned_lifecycle::run(command, Duration::from_secs(60)).unwrap();
            assert!(output.status.success(), "fixture compile: {output:?}");
            fixture
        }

        fn run(&self) -> String {
            let command = Command::new(self.0.join("probe"));
            println!("actual fixture run: {command:?}");
            let (output, _) = owned_lifecycle::run(command, Duration::from_secs(120)).unwrap();
            assert!(output.status.success(), "fixture run: {output:?}");
            String::from_utf8(output.stdout).unwrap()
        }
    }

    #[test]
    fn aarch64_trap_kernel_semantics() {
        let out = Fixture::build().run();
        let m = parse_measurements(&out)
            .unwrap_or_else(|error| panic!("{error} in probe output:\n{out}"));
        let check = |result: Result<(), String>| {
            result.unwrap_or_else(|error| panic!("{error} in probe output:\n{out}"));
        };
        // Page size is environment input (4 KiB and 64 KiB hosts both run
        // this): the probe must observe exactly what the runtime queries.
        check(m.check_i64(
            "P0_PAGESZ",
            reverie_inguest::arch::page_size().unwrap() as i64,
        ));
        // Filter-visible IP for svc is the following instruction, and the
        // siginfo call address equals the frame pc.
        check(m.check_i64("P1_CALL_MINUS_SITE", 4));
        check(m.check_i64("P1_PC_MINUS_SITE", 4));
        check(m.check_i64("P1_CALL_MINUS_PC", 0));
        check(m.check_i64("P1_SI_CODE", 1));
        check(m.check_hex("P1_SI_ARCH", 0xc000_00b7));
        // Regression: verdicts from raw returns with a pre-install pid.
        check(m.check_str("P1_IP_CANDIDATE_SITE", "NO"));
        check(m.check_str("P1_IP_CANDIDATE_SITE_PLUS4", "MATCH"));
        // Arguments arrive intact; one result write resumes after the svc.
        check(m.check_i64("P2_ARGS_INTACT_X0_TO_X5", 1));
        check(m.check_i64("P3_RESUME_OK", 1));
        // The private restorer returns at its svc + 4.
        check(m.check_i64("P4_RETURNED", 888));
        assert_eq!(
            result_exit(&out, "P4_RESTORER_SVC_PLUS4").unwrap(),
            ("EXITED".to_string(), Some(0))
        );
        // Sustained trapping, BTI landing pads, SVE records, inheritance.
        check(m.check_i64("P5_ENTRIES", 100));
        check(m.check_i64("P5_BAD_RESULTS", 0));
        check(m.check_str("P6_BTI_C_BLR", "OK"));
        check(m.check_str("P6_BTI_J_BR", "OK"));
        check(m.check_str("P6_BTI_JC_BLR", "OK"));
        check(m.check_hex("P7_REC_0_MAGIC", 0x4650_8001)); // FPSIMD_MAGIC
        check(m.check_i64("P8_FORK_CHILD_EXIT", 0));
        check(m.check_i64("P8_TSYNC_THREAD_RET", 555));
        // Trap filters stack over a pre-installed allowlist filter.
        check(m.check_i64("P11_SECCOMP_STACK_TRAP_OK", 1));
        // Syscall user dispatch: a measured trap or a named absence.
        assert!(
            m.check_i64("P9_SUD_TRAP_OK", 1).is_ok() || m.contains("P9_SUD_ENABLE_FAIL_ERRNO"),
            "SUD neither trapped nor reported its absence:\n{out}"
        );
        check(m.check_i64("PROBE_DONE", 1));
    }
}
