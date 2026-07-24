/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

fn main() {
    let value = match std::env::args().nth(1).as_deref().unwrap_or("home") {
        "home" => env!("REVERIE_DBI_DYNAMORIO_HOME"),
        "cmake" => env!("REVERIE_DBI_DYNAMORIO_CMAKE"),
        "drrun" => env!("REVERIE_DBI_DYNAMORIO_DRRUN"),
        argument => {
            eprintln!("unknown artifact {argument:?}; expected home, cmake, or drrun");
            std::process::exit(2);
        }
    };
    println!("{value}");
}
