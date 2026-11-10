/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

fn main() {
    println!("cargo:rerun-if-changed=src/terminal_read.c");
    println!("cargo:rerun-if-changed=src/terminal_read.h");
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64") {
        return;
    }
    cc::Build::new()
        .file("src/terminal_read.c")
        .flag("-std=c11")
        .flag("-pthread")
        // glibc's public pthread_cleanup macros unwind only this C stack.
        .flag("-fexceptions")
        .compile("reverie_kvm_terminal_read");
    println!("cargo:rustc-link-lib=pthread");
}
