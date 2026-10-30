/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(all(not(sanitized), test))]
#[path = "tool_fixtures/vdso.rs"]
mod vdso_tool;

#[cfg(all(not(sanitized), test))]
use vdso_tool::LocalState;

#[cfg(all(not(sanitized), test))]
#[path = "support/vdso_rust_guest.rs"]
mod rust_guest;

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::mem::MaybeUninit;

    use reverie_ptrace::testing::check_fn;

    use super::*;

    #[test]
    #[should_panic]
    fn run_guest_vdso_tod_test() {
        check_fn::<LocalState, _>(rust_guest::tod);
    }

    #[test]
    fn run_guest_vdso_getcpu_test() {
        struct VdsoHandle(*mut libc::c_void);

        impl Drop for VdsoHandle {
            fn drop(&mut self) {
                unsafe { libc::dlclose(self.0) };
            }
        }

        type Getcpu = unsafe extern "C" fn(
            *mut libc::c_uint,
            *mut libc::c_uint,
            *mut libc::c_void,
        ) -> libc::c_long;

        // Resolve in the parent: loader operations are unsafe after a threaded
        // fork, and sched_getcpu may read rseq TLS without entering the vDSO.
        let vdso_base = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) } as usize;
        assert_ne!(vdso_base, 0);
        let handle = unsafe {
            libc::dlerror();
            libc::dlopen(
                c"linux-vdso.so.1".as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            )
        };
        assert!(!handle.is_null());
        let handle = VdsoHandle(handle);
        assert!(unsafe { libc::dlerror() }.is_null());
        let symbol =
            unsafe { libc::dlvsym(handle.0, c"__vdso_getcpu".as_ptr(), c"LINUX_2.6".as_ptr()) };
        assert!(unsafe { libc::dlerror() }.is_null());
        assert!(!symbol.is_null());
        let mut info = MaybeUninit::uninit();
        assert_ne!(unsafe { libc::dladdr(symbol, info.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { info.assume_init() }.dli_fbase as usize, vdso_base);
        let getcpu = unsafe { std::mem::transmute::<*mut libc::c_void, Getcpu>(symbol) };

        check_fn::<LocalState, _>(move || {
            rust_guest::getcpu(getcpu, vdso_base);
        });
        drop(handle);
        #[cfg(feature = "dbt")]
        rust_getcpu_command();
    }

    #[test]
    fn run_guest_vdso_gettimeofday_test() {
        check_fn::<LocalState, _>(rust_guest::gettimeofday);
        #[cfg(feature = "dbt")]
        rust_gettimeofday_command();
    }

    #[test]
    fn run_guest_vdso_clock_getres_test() {
        check_fn::<LocalState, _>(rust_guest::clock_getres);
        #[cfg(feature = "dbt")]
        rust_clock_getres_command();
    }
}

#[cfg(all(not(sanitized), test))]
#[path = "support/vdso_command.rs"]
mod command;

#[cfg(all(not(sanitized), test))]
fn assert_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "vdso command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status, reverie::ExitStatus::Exited(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[cfg(all(not(sanitized), test))]
#[test]
fn ptrace_vdso_command() {
    let guest = command::GuestBinary::compile();
    guest.assert_native();
    guest.record_before_launch("ptrace");
    let (output, ()) =
        reverie_test_support::test_cmd::<LocalState>(guest.program(), &["tool"]).unwrap();
    assert_command_output("ptrace", &output);
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
fn caller_manifest() -> std::path::PathBuf {
    let executable = std::env::current_exe().unwrap();
    executable
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("reverie-dbt-callers")
        .join("vdso")
        .join("manifest.json")
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
#[test]
fn dbt_vdso_command() {
    let manifest = caller_manifest();
    reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let guest = command::GuestBinary::compile();
    guest.assert_native();
    guest.record_before_launch("dbt");
    let (output, ()) = reverie_test_support::test_dbt_cmd_with_config::<LocalState>(
        guest.program(),
        &["tool"],
        (),
        &manifest,
    )
    .unwrap();
    assert_command_output("dbt", &output);
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
#[test]
fn dbt_vdso_missing_artifact_refuses() {
    let manifest = caller_manifest();
    let _valid_default = reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let missing = manifest.with_file_name("missing-vdso-manifest.json");
    assert!(!missing.exists());
    let error = reverie_test_support::test_dbt_cmd_with_config::<LocalState>(
        "/bin/true",
        &[],
        (),
        &missing,
    )
    .unwrap_err();
    eprintln!(
        "explicit missing vdso artifact {}: {error}",
        missing.display()
    );
    let reverie::Error::Io(error) = error else {
        panic!("expected missing manifest I/O error: {error}");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
fn rust_clock_getres_command() {
    let manifest = caller_manifest();
    reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let program = env!("CARGO_BIN_EXE_vdso-rust-command-guest");
    eprintln!("vdso Rust clock_getres command: image={program}");

    let (output, ()) = reverie_test_support::test_cmd::<LocalState>(program, &[]).unwrap();
    assert_command_output("rust/clock_getres/ptrace", &output);

    let (output, ()) =
        reverie_test_support::test_dbt_cmd_with_config::<LocalState>(program, &[], (), &manifest)
            .unwrap();
    assert_command_output("rust/clock_getres/dbt", &output);
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
fn gettimeofday_command_output_matches(output: &reverie::process::Output) -> bool {
    output.status == reverie::ExitStatus::Exited(0)
        && output.stdout.as_slice() == b"vdso-rust-gettimeofday-complete\n"
        && output.stderr.is_empty()
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
fn assert_gettimeofday_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "vdso command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert!(gettimeofday_command_output_matches(output));
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
fn rust_gettimeofday_command() {
    let manifest = caller_manifest();
    reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let program = env!("CARGO_BIN_EXE_vdso-rust-command-guest");
    eprintln!("vdso Rust gettimeofday command: image={program}");

    let (control, ()) =
        reverie_test_support::test_dbt_cmd_with_config::<LocalState>(program, &[], (), &manifest)
            .unwrap();
    assert_command_output("rust/gettimeofday/control-clock_getres/dbt", &control);
    assert!(!gettimeofday_command_output_matches(&control));
    eprintln!("vdso Rust gettimeofday control: clock_getres rejected=true");

    let (output, ()) =
        reverie_test_support::test_cmd::<LocalState>(program, &["gettimeofday"]).unwrap();
    assert_gettimeofday_command_output("rust/gettimeofday/ptrace", &output);

    let (output, ()) = reverie_test_support::test_dbt_cmd_with_config::<LocalState>(
        program,
        &["gettimeofday"],
        (),
        &manifest,
    )
    .unwrap();
    assert_gettimeofday_command_output("rust/gettimeofday/dbt", &output);
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
fn getcpu_command_output_matches(output: &reverie::process::Output) -> bool {
    output.status == reverie::ExitStatus::Exited(0)
        && output.stdout == b"vdso-rust-getcpu-complete\n"
        && output.stderr.is_empty()
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
fn assert_getcpu_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "vdso command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert!(getcpu_command_output_matches(output));
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
fn rust_getcpu_command() {
    let manifest = caller_manifest();
    reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let program = env!("CARGO_BIN_EXE_vdso-rust-command-guest");
    eprintln!("vdso Rust getcpu command: image={program}");

    let (output, ()) = reverie_test_support::test_cmd::<LocalState>(program, &["getcpu"]).unwrap();
    assert_getcpu_command_output("rust/getcpu/ptrace", &output);

    let (output, ()) = reverie_test_support::test_dbt_cmd_with_config::<LocalState>(
        program,
        &["getcpu"],
        (),
        &manifest,
    )
    .unwrap();
    assert_getcpu_command_output("rust/getcpu/dbt", &output);

    let (output, ()) =
        reverie_test_support::test_dbt_cmd_with_config::<LocalState>(program, &[], (), &manifest)
            .unwrap();
    assert_command_output("rust/getcpu/control-clock_getres/dbt", &output);
    assert!(!getcpu_command_output_matches(&output));
    eprintln!("vdso Rust getcpu control: clock_getres rejected=true");
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
fn tod_command_output_matches(output: &reverie::process::Output) -> bool {
    output.status == reverie::ExitStatus::Exited(0)
        && output.stdout.as_slice()
            == concat!(
                r#"called `Result::unwrap()` on an `Err` value: Os { code: 22, kind: InvalidInput, message: "Invalid argument" }"#,
                "\nvdso-rust-tod-unwind-complete\n",
            )
            .as_bytes()
        && output.stderr.is_empty()
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
fn assert_tod_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "vdso command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert!(tod_command_output_matches(output));
}

#[cfg(all(not(sanitized), test, feature = "dbt"))]
#[test]
fn rust_vdso_tod_command() {
    let manifest = caller_manifest();
    reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let program = env!("CARGO_BIN_EXE_vdso-rust-command-guest");
    eprintln!("vdso Rust tod command: image={program}");

    let (output, ()) = reverie_test_support::test_cmd::<LocalState>(program, &["tod"]).unwrap();
    assert_tod_command_output("rust/tod/ptrace", &output);

    let (output, ()) = reverie_test_support::test_dbt_cmd_with_config::<LocalState>(
        program,
        &["tod"],
        (),
        &manifest,
    )
    .unwrap();
    assert_tod_command_output("rust/tod/dbt", &output);

    let (output, ()) =
        reverie_test_support::test_dbt_cmd_with_config::<LocalState>(program, &[], (), &manifest)
            .unwrap();
    assert_command_output("rust/tod/control-clock_getres/dbt", &output);
    assert!(!tod_command_output_matches(&output));
    eprintln!("vdso Rust tod control: clock_getres rejected=true");
}
