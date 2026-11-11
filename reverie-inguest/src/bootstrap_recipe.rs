/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The production compiler recipe for the `native_exec/` bootstrap
//! sources, exported next to the sources it compiles.

/// Compiler flags, in order, that a producer passes to `cc` before
/// `-c <source> -o <object>` when compiling `private-entry.S`,
/// `private-bootstrap.c`, `private-fs.S`, `private-kernel-state.c`
/// and `private-maps.c` into the bootstrap image.
///
/// This list is the single source of truth. The zone-B checker
/// (`reverie-inguest/tests/zone_b_no_tls.rs`) compiles with exactly
/// these flags. Hermit's `liteinst-runtime-build/artifact.rs` still
/// carries its own copy; adopting this export there happens in a
/// later Hermit pin bump, not with the change that introduced it.
/// Until then the two copies must be edited together — a flag added
/// only on one side silently un-pins the checker from production.
///
/// `-fno-jump-tables` (from <https://github.com/rrnewton/hermit/pull/5293>,
/// landed as hermit 38111a07) sits immediately after
/// `-mcmodel=large`, matching the Hermit producer's argument order.
///
/// This module is deliberately not feature-gated and has no
/// dependencies: the checker builds under feature sets that do not
/// enable the native-exec machinery, and the recipe must be
/// available there too.
pub const BOOTSTRAP_RECIPE: &[&str] = &[
    "-O2",
    "-g",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-fno-stack-protector",
    "-fno-builtin",
    "-ffreestanding",
    "-fno-asynchronous-unwind-tables",
    "-fcf-protection=branch",
    "-mcmodel=large",
    "-fno-jump-tables",
    "-fno-pic",
    "-fno-pie",
    "-DEXEC_PRIVATE_BOOTSTRAP_IMAGE",
];
