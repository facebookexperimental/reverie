#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is dual-licensed under either the MIT license found in
# the LICENSE-MIT file in the root directory of this source tree or the
# Apache License, Version 2.0 found in the LICENSE-APACHE file in the
# root directory of this source tree. You may select, at your option, one
# of the above-listed licenses.
"""Refuse compile-time CARGO env! in reverie-liteinst-artifact.

env!("CARGO...") bakes the compiling machine's paths into a test, so
a Buck test-mode build (remote execution, staged sources) reads the
wrong tree or fails to compile. Tests here read CARGO_MANIFEST_DIR
at run time instead (reverie_workspace_root in lib.rs; Cargo sets
the variable when it runs a test and the Buck unittest target
points it into staged sources). This gate scans the crate's
src/**/*.rs and fails on any env!("CARGO..."). The four
grandfathered lines this gate once allowed (a cargo-metadata probe
and a Cargo-executable witness in lib.rs, a source-path walk in the
catalogued preparation_identity.rs) were converted to run-time
reads and their allowances deleted in the same changes, so the
allowlist is empty: any compile-time use is refused by name. The
tests/ self-checks are out of scope: their Buck targets set
CARGO_MANIFEST_DIR explicitly for a checkout run.

Exit 0: no unallowed use. Exit 1: unallowed uses (named). Exit 2:
the crate tree could not be read.
"""

import argparse
import pathlib
import sys

ALLOWED = {}
NEEDLE = 'env!("CARGO'


def main():
    here = pathlib.Path(__file__).absolute().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--crate",
        type=pathlib.Path,
        default=here.parent / "reverie-liteinst-artifact",
        help="crate directory (default: ../reverie-liteinst-artifact)",
    )
    args = parser.parse_args()
    src = args.crate / "src"
    if not src.is_dir():
        print(f"crate sources not found: {src}", file=sys.stderr)
        return 2
    offenders = []
    allowed = 0
    for path in sorted(src.rglob("*.rs")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if NEEDLE not in line:
                continue
            if line.strip() in ALLOWED.get(path.name, set()):
                allowed += 1
            else:
                offenders.append(f"{path}:{number}: {line.strip()}")
    if offenders:
        print(
            "compile-time CARGO env! refused in reverie-liteinst-artifact; "
            "read the variable at run time instead (see reverie_workspace_root):",
            file=sys.stderr,
        )
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        return 1
    print(f"env gate ok: {allowed} allowed compile-time use(s), no unallowed ones")
    return 0


if __name__ == "__main__":
    sys.exit(main())
