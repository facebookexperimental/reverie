# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is dual-licensed under either the MIT license found in the
# LICENSE-MIT file in the root directory of this source tree or the Apache
# License, Version 2.0 found in the LICENSE-APACHE file in the root directory
# of this source tree. You may select, at your option, one of the
# above-listed licenses.

load("@fbcode_macros//build_defs:export_files.bzl", "buck_export_file")

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
# The open-source stand-in exports the same names (these two
# constants and the export definition below) with that tree's
# liteinst-runtime configuration as the constraint, so the
# shared BUCK files resolve in both cells.
LITEINST_RUNTIME_FLAGS_CONSTRAINT = "fbcode//hermetic_infra/reverie/constraints:liteinst-runtime-flags[applied]"
LITEINST_RUNTIME_SELECT_RUSTC_FLAGS = [
    "-Coverflow-checks=yes",
    "-Ccodegen-units=16",
    "-Cdebuginfo=0",
]

def liteinst_runtime_flags_export():
    # This file as a resource of the packaged cross-check, whose
    # profile comparison resolves the alias's flags-constraint
    # constant from its text. Only the package holding the file
    # can export it, and this file is per-tree: the open-source
    # trees carry no such file in this package (their stand-in
    # lives in the shim cell), so a shared BUCK file must not name
    # it as a source. The definition therefore lives here, in the
    # per-tree file, and only takes effect where the cross-check
    # runs: fbsource, whose root config has no [oss] section. The
    # open-source stand-in carries this same definition; there
    # the root config sets [oss] internal_cell, this returns
    # without defining a target, and nothing references one, so
    # the package configures without the per-tree file.
    if read_root_config("oss", "internal_cell", "") != "":
        return

    buck_export_file(
        name = "liteinst-runtime-flags.bzl",
        visibility = ["//hermetic_infra/..."],
    )
