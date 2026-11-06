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
//! host page size (targeted hosts run both 4 KiB and 64 KiB pages). This
//! test builds the probe with `cc`, runs it, and asserts on its raw
//! `KEY=VALUE` measurements, so a kernel or probe change that breaks a
//! pinned relation fails here instead of inside the runtime.
//!
//! Regression pinned by name: the probe's P1 verdict strings derive from a
//! pid cached *before* the discriminating filter installs (comparing
//! against a `getpid()` issued under the filter inverts MATCH/NO), and
//! this test asserts `SITE=NO` / `SITE_PLUS4=MATCH` from the raw returns.
//!
//! Syscall user dispatch is capability-dependent (targeted kernels may be
//! built without it): the test accepts either a measured trap or an
//! explicit enable failure, and fails on anything else.

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

    fn assert_line(out: &str, prefix: &str) {
        assert!(
            out.lines().any(|line| line.starts_with(prefix)),
            "missing or wrong measurement {prefix:?} in probe output:\n{out}"
        );
    }

    #[test]
    fn aarch64_trap_kernel_semantics() {
        let out = Fixture::build().run();
        // Page size is environment input (4 KiB and 64 KiB hosts both run
        // this): the probe must observe exactly what the runtime queries.
        assert_line(
            &out,
            &format!("P0_PAGESZ={}", reverie_inguest::arch::page_size()),
        );
        // Filter-visible IP for svc is the following instruction, and the
        // siginfo call address equals the frame pc.
        assert_line(&out, "P1_CALL_MINUS_SITE=+4");
        assert_line(&out, "P1_PC_MINUS_SITE=+4");
        assert_line(&out, "P1_CALL_MINUS_PC=+0");
        assert_line(&out, "P1_SI_CODE=1");
        assert_line(&out, "P1_SI_ARCH=0xc00000b7");
        // Regression: verdicts from raw returns with a pre-install pid.
        assert_line(&out, "P1_IP_CANDIDATE_SITE=NO");
        assert_line(&out, "P1_IP_CANDIDATE_SITE_PLUS4=MATCH");
        // Arguments arrive intact; one result write resumes after the svc.
        assert_line(&out, "P2_ARGS_INTACT_X0_TO_X5=1");
        assert_line(&out, "P3_RESUME_OK=1");
        // The private restorer returns at its svc + 4.
        assert_line(&out, "P4_RETURNED=888");
        assert_line(&out, "RESULT P4_RESTORER_SVC_PLUS4 STATUS=EXITED CODE=0");
        // Sustained trapping, BTI landing pads, SVE records, inheritance.
        assert_line(&out, "P5_ENTRIES=100");
        assert_line(&out, "P5_BAD_RESULTS=0");
        assert_line(&out, "P6_BTI_C_BLR=OK");
        assert_line(&out, "P6_BTI_J_BR=OK");
        assert_line(&out, "P6_BTI_JC_BLR=OK");
        assert_line(&out, "P7_REC_0_MAGIC=0x46508001"); // FPSIMD_MAGIC
        assert_line(&out, "P8_FORK_CHILD_EXIT=0");
        assert_line(&out, "P8_TSYNC_THREAD_RET=555");
        // Trap filters stack over a pre-installed allowlist filter.
        assert_line(&out, "P11_SECCOMP_STACK_TRAP_OK=1");
        // Syscall user dispatch: a measured trap or a named absence.
        assert!(
            out.contains("P9_SUD_TRAP_OK=1") || out.contains("P9_SUD_ENABLE_FAIL_ERRNO="),
            "SUD neither trapped nor reported its absence:\n{out}"
        );
        assert_line(&out, "PROBE_DONE=1");
    }
}
