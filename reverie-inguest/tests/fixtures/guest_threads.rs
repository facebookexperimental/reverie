/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Dynamic std program: the actual clone/clone3 must be journaled and refused.
use std::io::Write;

fn main() {
    println!("THREAD_CLONE_REQUEST");
    std::io::stdout().flush().unwrap();
    let child = std::thread::spawn(|| println!("UNEXPECTED_GUEST_THREAD_RAN"));
    child.join().unwrap();
    panic!("the probe admitted a guest thread outside its test domain");
}
