/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../support/vdso_rust_guest.rs"]
mod rust_guest;

fn main() -> std::process::ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [] => rust_guest::clock_getres(),
        [selector] if selector == "gettimeofday" => gettimeofday_command(),
        [selector] if selector == "getcpu" => getcpu_command(),
        _ => {
            eprintln!("usage: vdso-rust-command-guest [gettimeofday|getcpu]");
            return std::process::ExitCode::from(2);
        }
    }
    std::process::ExitCode::SUCCESS
}

fn gettimeofday_command() {
    use std::io::Write;

    rust_guest::gettimeofday();
    std::io::stdout()
        .write_all(b"vdso-rust-gettimeofday-complete\n")
        .unwrap();
}

fn getcpu_command() {
    use std::io::Write;
    use std::mem::MaybeUninit;

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

    // Resolve in this command process: the parent's vDSO address is not shared.
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

    rust_guest::getcpu(getcpu, vdso_base);
    drop(handle);
    std::io::stdout()
        .write_all(b"vdso-rust-getcpu-complete\n")
        .unwrap();
}
