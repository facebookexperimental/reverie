/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! L1 seam (aarch64): the LiteInst bootstrap installer serves by trap.
//!
//! With no coordinator listening it runs the allocator preflight and the
//! continuation (on the legacy stack, the only backing aarch64 admits) and
//! fails at the coordinator connect, which the shared installer reaches
//! before it installs any filter or SIGSYS handler. The aarch64 refusal this
//! replaces, a ToolRegion page-size refusal (64 KiB pages) or the
//! unsupported fixed-arena status (4 KiB pages) would each fail here.
//!
//! The installer runs in a re-executed child, because the continuation
//! registers process-global state before the connect fails. This file
//! declares the legacy allocator the preflight requires (the lib's own unit
//! test binary declares none). It has no test on other architectures.

reverie_liteinst::declare_legacy_scoped_tool_allocator!();

#[cfg(target_arch = "aarch64")]
#[test]
fn aarch64_bootstrap_install_reaches_coordinator_connect() {
    const CHILD: &str = "REVERIE_LITEINST_AARCH64_BOOTSTRAP_CHILD";
    const NAME: &str = "aarch64_bootstrap_install_reaches_coordinator_connect";
    if std::env::var_os(CHILD).is_some() {
        let mut before: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: a query only (null new action) into a zeroed sigaction.
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGSYS, std::ptr::null(), &mut before) },
            0
        );
        // SAFETY: an isolated child process; it only reports and exits.
        let error = unsafe {
            reverie_liteinst::install_tool_from_bootstrap::<()>("/nonexistent-coordinator")
        }
        .unwrap_err();
        let text = error.to_string();
        assert_ne!(error.kind(), std::io::ErrorKind::Unsupported, "{text}");
        assert!(!text.contains("not supported on aarch64"), "{text}");
        assert!(!text.contains("tool region layout requires"), "{text}");
        assert!(text.contains("rpc i/o error"), "{text}");
        assert!(text.contains("errno 2"), "{text}");
        let mut after: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGSYS, std::ptr::null(), &mut after) },
            0
        );
        // The whole disposition is unchanged: handler, flags and mask.
        assert_eq!(after.sa_sigaction, before.sa_sigaction);
        assert_eq!(after.sa_flags, before.sa_flags);
        // The mask is compared signal by signal over the kernel's set.
        // glibc's sigaction copies all of its sigset_t out of an
        // uninitialized kernel_sigaction, while the kernel fills only
        // _NSIG/8 bytes of it, so the bytes past the kernel's set are
        // stack garbage in both and must not be compared.
        let differing = |a: &libc::sigset_t, b: &libc::sigset_t| -> Vec<libc::c_int> {
            (1..=libc::SIGRTMAX())
                .filter(|&signal| {
                    // SAFETY: both sets are initialized sigset_t values.
                    let (x, y) =
                        unsafe { (libc::sigismember(a, signal), libc::sigismember(b, signal)) };
                    assert!(x >= 0 && y >= 0, "sigismember failed for signal {signal}");
                    x != y
                })
                .collect()
        };
        assert_eq!(
            differing(&before.sa_mask, &after.sa_mask),
            Vec::<libc::c_int>::new()
        );
        // Control: the comparison sees a one-signal change.
        let mut toggled = before.sa_mask;
        // SAFETY: an initialized set and a valid signal number.
        unsafe {
            if libc::sigismember(&toggled, libc::SIGUSR1) == 1 {
                libc::sigdelset(&mut toggled, libc::SIGUSR1);
            } else {
                libc::sigaddset(&mut toggled, libc::SIGUSR1);
            }
        }
        assert_eq!(differing(&before.sa_mask, &toggled), vec![libc::SIGUSR1]);
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        assert!(
            status
                .lines()
                .any(|line| line.split_whitespace().eq(["Seccomp:", "0"])),
            "{status}"
        );
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("1 passed"),
        "the exact bootstrap child must execute"
    );
}
