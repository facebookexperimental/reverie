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
        rust_getcpu_command();
    }

    #[test]
    fn run_guest_vdso_gettimeofday_test() {
        check_fn::<LocalState, _>(rust_guest::gettimeofday);
        rust_gettimeofday_command();
    }

    #[test]
    fn run_guest_vdso_clock_getres_test() {
        check_fn::<LocalState, _>(rust_guest::clock_getres);
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

#[cfg(all(not(sanitized), test))]
fn rust_clock_getres_command() {
    let program = reverie_test_support::guest_binary!("vdso-rust-command-guest");
    eprintln!("vdso Rust clock_getres command: image={program}");

    let (output, ()) = reverie_test_support::test_cmd::<LocalState>(program, &[]).unwrap();
    assert_command_output("rust/clock_getres/ptrace", &output);
}

/// Run the command image with no selector (its clock_getres body) under
/// ptrace: a real successful run whose output another selector's oracle must
/// reject.
#[cfg(all(not(sanitized), test))]
fn clock_getres_control(label: &str) -> reverie::process::Output {
    let program = reverie_test_support::guest_binary!("vdso-rust-command-guest");
    let (control, ()) = reverie_test_support::test_cmd::<LocalState>(program, &[]).unwrap();
    assert_command_output(
        &format!("rust/{label}/control-clock_getres/ptrace"),
        &control,
    );
    control
}

#[cfg(all(not(sanitized), test))]
fn gettimeofday_command_output_matches(output: &reverie::process::Output) -> bool {
    output.status == reverie::ExitStatus::Exited(0)
        && output.stdout.as_slice() == b"vdso-rust-gettimeofday-complete\n"
        && output.stderr.is_empty()
}

#[cfg(all(not(sanitized), test))]
fn assert_gettimeofday_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "vdso command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert!(gettimeofday_command_output_matches(output));
}

#[cfg(all(not(sanitized), test))]
fn rust_gettimeofday_command() {
    let program = reverie_test_support::guest_binary!("vdso-rust-command-guest");
    eprintln!("vdso Rust gettimeofday command: image={program}");

    let control = clock_getres_control("gettimeofday");
    assert!(!gettimeofday_command_output_matches(&control));
    eprintln!("vdso Rust gettimeofday control: clock_getres rejected=true");

    let (output, ()) =
        reverie_test_support::test_cmd::<LocalState>(program, &["gettimeofday"]).unwrap();
    assert_gettimeofday_command_output("rust/gettimeofday/ptrace", &output);
}

#[cfg(all(not(sanitized), test))]
fn getcpu_command_output_matches(output: &reverie::process::Output) -> bool {
    output.status == reverie::ExitStatus::Exited(0)
        && output.stdout == b"vdso-rust-getcpu-complete\n"
        && output.stderr.is_empty()
}

#[cfg(all(not(sanitized), test))]
fn assert_getcpu_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "vdso command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert!(getcpu_command_output_matches(output));
}

#[cfg(all(not(sanitized), test))]
fn rust_getcpu_command() {
    let program = reverie_test_support::guest_binary!("vdso-rust-command-guest");
    eprintln!("vdso Rust getcpu command: image={program}");

    let (output, ()) = reverie_test_support::test_cmd::<LocalState>(program, &["getcpu"]).unwrap();
    assert_getcpu_command_output("rust/getcpu/ptrace", &output);

    let control = clock_getres_control("getcpu");
    assert!(!getcpu_command_output_matches(&control));
    eprintln!("vdso Rust getcpu control: clock_getres rejected=true");
}

#[cfg(all(not(sanitized), test))]
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

#[cfg(all(not(sanitized), test))]
fn assert_tod_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "vdso command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert!(tod_command_output_matches(output));
}

#[cfg(all(not(sanitized), test))]
#[test]
fn rust_vdso_tod_command() {
    let program = reverie_test_support::guest_binary!("vdso-rust-command-guest");
    eprintln!("vdso Rust tod command: image={program}");

    let (output, ()) = reverie_test_support::test_cmd::<LocalState>(program, &["tod"]).unwrap();
    assert_tod_command_output("rust/tod/ptrace", &output);

    let control = clock_getres_control("tod");
    assert!(!tod_command_output_matches(&control));
    eprintln!("vdso Rust tod control: clock_getres rejected=true");
}
