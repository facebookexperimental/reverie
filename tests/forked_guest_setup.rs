/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A guest forked from a function (`spawn_fn`) whose setup fails before its
//! stop for tracing ends with a message naming the failed step, and the spawn
//! returns an error carrying it. Neither the guest nor the tracer hangs.
//!
//! The failure is injected in a child process of the test, the scenario,
//! which installs a seccomp filter that fails personality(2) with ENOSYS, as
//! some sandboxes' filters do, and then spawns the guest. The filter stays in
//! that process and its children.

#[cfg(all(not(sanitized), test))]
use reverie::Tool;

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default, Clone)]
struct NoopTool;

#[cfg(all(not(sanitized), test))]
#[reverie::tool]
impl Tool for NoopTool {
    type GlobalState = ();
    type ThreadState = ();
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Duration;

    use reverie_ptrace::testing::test_fn;

    use super::*;

    /// Set in the scenario's environment.
    const SCENARIO_ENV: &str = "REVERIE_FORKED_GUEST_SETUP_SCENARIO";

    /// This test's name, which the scenario runs alone.
    const TEST_NAME: &str = "tests::a_failed_setup_step_ends_the_guest_with_a_message";

    /// How long the scenario may take; a hang outlasts it.
    const SCENARIO_TIMEOUT: Duration = Duration::from_secs(120);

    /// Marks the scenario's report on its stdout.
    const REPORT: &str = "SCENARIO-RESULT: ";

    /// A classic BPF statement and jump (linux/filter.h).
    fn statement(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    /// Installs, for every thread of this process and its future children, a
    /// seccomp filter that fails personality(2) with ENOSYS and allows every
    /// other system call.
    fn fail_personality_with_enosys() {
        const BPF_LD_W_ABS: u16 = 0x00 | 0x00 | 0x20;
        const BPF_JMP_JEQ_K: u16 = 0x05 | 0x10 | 0x00;
        const BPF_RET_K: u16 = 0x06 | 0x00;
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
        const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
        const SECCOMP_FILTER_FLAG_TSYNC: libc::c_long = 1;
        // struct seccomp_data: the syscall number at offset 0, the audit
        // architecture at 4 (linux/seccomp.h, linux/audit.h).
        #[cfg(target_arch = "x86_64")]
        const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
        #[cfg(target_arch = "aarch64")]
        const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;

        let mut filter = [
            statement(BPF_LD_W_ABS, 4),
            jump(BPF_JMP_JEQ_K, AUDIT_ARCH_NATIVE, 0, 3),
            statement(BPF_LD_W_ABS, 0),
            jump(BPF_JMP_JEQ_K, libc::SYS_personality as u32, 0, 1),
            statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
            statement(BPF_RET_K, SECCOMP_RET_ALLOW),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: prctl and seccomp take integers and a filter program that
        // outlives the call.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_SET_MODE_FILTER,
                    SECCOMP_FILTER_FLAG_TSYNC,
                    &program as *const libc::sock_fprog,
                ),
                0,
                "install the seccomp filter: {}",
                std::io::Error::last_os_error()
            );
        }
        // SAFETY: personality with 0xffffffff only reads the persona.
        let persona = unsafe { libc::personality(0xffff_ffff) };
        assert_eq!(
            (persona, std::io::Error::last_os_error().raw_os_error()),
            (-1, Some(libc::ENOSYS)),
            "the filter fails personality(2) with ENOSYS"
        );
    }

    /// The scenario: spawns a guest under the filter, and reports on its
    /// stdout what the spawn returned.
    fn scenario() {
        fail_personality_with_enosys();
        let report = match test_fn::<NoopTool, _>(|| {}) {
            Ok((output, ())) => format!("the guest ran and exited with {:?}", output.status),
            Err(error) => format!("error: {error:#}"),
        };
        println!("{REPORT}{}", report.replace('\n', " | "));
    }

    #[test]
    fn a_failed_setup_step_ends_the_guest_with_a_message() {
        if std::env::var_os(SCENARIO_ENV).is_some() {
            return scenario();
        }

        // The scenario runs in a process group of its own, so that a hang
        // kills it and its guest, never this test's own group.
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(SCENARIO_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("start the scenario");
        let pid = child.id() as libc::pid_t;
        // SAFETY: getpgid and getpgrp take and return integers.
        let (group, own_group) = unsafe { (libc::getpgid(pid), libc::getpgrp()) };
        assert!(
            group == pid && group != own_group,
            "the scenario leads its own process group"
        );
        let (done, finished) = mpsc::channel();
        // wait_with_output reads stdout and stderr concurrently.
        std::thread::spawn(move || done.send(child.wait_with_output()));
        let Ok(output) = finished.recv_timeout(SCENARIO_TIMEOUT) else {
            // SAFETY: kill takes integers; the group is the scenario's.
            unsafe { libc::kill(-group, libc::SIGKILL) };
            panic!("the scenario hung for {SCENARIO_TIMEOUT:?} after its guest's setup failed");
        };
        let output = output.expect("wait for the scenario");
        let status = output.status;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let report = stdout
            .lines()
            .find_map(|line| line.strip_prefix(REPORT))
            .unwrap_or_else(|| {
                panic!("the scenario reported nothing ({status}):\n{stdout}\n{stderr}")
            });
        assert!(
            status.success(),
            "the scenario failed ({status}):\n{stdout}\n{stderr}"
        );
        for expected in [
            "exited during ptrace initialization with Exited(127)",
            "Reverie could not disable address-space randomization with personality(2)",
            "Reverie's forked guest could not prepare itself for tracing: ENOSYS",
        ] {
            assert!(report.contains(expected), "{expected:?} not in: {report}");
        }
    }
}
