# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is dual-licensed under either the MIT license found in the
# LICENSE-MIT file in the root directory of this source tree or the Apache
# License, Version 2.0 found in the LICENSE-APACHE file in the root directory
# of this source tree. You may select, at your option, one of the
# above-listed licenses.

# The liteinst-runtime rustc flags that no fbcode build-mode or rust
# toolchain constraint encodes, delivered per target: every rust
# target in the liteinst-runtime closure (this tree's own targets in
# their shared BUCK files, its consumers' targets, and the vendored
# crates through third-party fixups) appends
# `select({LITEINST_RUNTIME_FLAGS_CONSTRAINT: LITEINST_RUNTIME_SELECT_RUSTC_FLAGS, "DEFAULT": []})`
# to its rustc_flags, and the liteinst-runtime configured alias adds
# the constraint to the closure's configuration. These two names
# live in this minimal package, next to the constraint they name, so
# every consumer depends on nothing else here; the profile that
# defines the alias re-exports them for the alias and for compat.
# The open-source stand-in exports the same two names with that
# tree's liteinst-runtime configuration as the constraint, so the
# shared BUCK files resolve in both cells.
LITEINST_RUNTIME_FLAGS_CONSTRAINT = "fbcode//hermetic_infra/reverie/constraints:liteinst-runtime-flags[applied]"
LITEINST_RUNTIME_SELECT_RUSTC_FLAGS = [
    "-Coverflow-checks=yes",
    "-Ccodegen-units=16",
    "-Cdebuginfo=0",
]
