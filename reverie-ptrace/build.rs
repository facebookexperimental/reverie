/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    // Ubuntu's libunwind-ptrace needs symbols from Libs.private (notably LZMA)
    // even when linked dynamically. Ask pkg-config for those dependencies, but
    // leave Config::statik unset: --static here controls dependency discovery,
    // while the normal pkg-config environment still chooses the link mode.
    pkg_config::Config::new()
        .arg("--static")
        .probe("libunwind-ptrace")
        .expect("libunwind-ptrace development files and their dependencies are required");
}
