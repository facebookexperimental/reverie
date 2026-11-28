#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Refuse, by name, any stable-list exception that a stable-list build enables.

scripts/stable-features.sh names STABLE_FEATURE_EXCEPTIONS: workspace features
that no build with STABLE_FEATURES or STABLE_FEATURES_REGULAR may enable. For
each list this asks cargo's own resolver instead of modelling it:
`cargo metadata --locked --features "<list>"`, without --no-deps, resolves the
whole workspace as a build with that list would, with every member's default
features, every non-optional dependency's feature requests, optional
dependencies and the `dep:` and `?` forms, unified across targets and build
and dev units. Every exception that the resolve enables on a workspace package
(`resolve.nodes[].features`) is refused by name. A second resolve with no
--features tells the causes apart: an exception that is on even without the
list is labelled "always on" (a default or a non-optional dependency request);
any other is labelled "enabled by" the list.

Why cargo's resolver (the preferred form): it applies every rule cargo applies,
including any a hand model would miss. It runs with --locked and without
--offline, the network policy of validation's own cargo steps: a full resolve
needs every crate in the lock for every platform, so it may fetch what a host's
cache lacks. CARGO_NET_OFFLINE=true forbids that where the cache is complete.
That cargo accepts the package-qualified list across the workspace for
`cargo metadata` is shown by the controls run, once its result is recorded in
the change's Test plan.

It fails closed, with exit 2: a list or the exception list missing, empty,
assigned more than once (also through export, declare, typeset, readonly or
local, or an array subscript) or not in the form NAME="..."; a malformed
token; an exception the workspace does not declare; a cargo metadata failure
or timeout; or any unexpected error.

Exit 0: no exception is enabled. Exit 1: refused, every enabled exception
named. Exit 2: the inputs could not be established.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "scripts" / "stable-features.sh"
LISTS = ("STABLE_FEATURES", "STABLE_FEATURES_REGULAR")
ASSIGN = r"\s*((export|declare|typeset|readonly|local)(\s+-\w+)*\s+)?{}(\[[^]]*\])?\+?="


class InputError(Exception):
    """An input the verdict needs could not be established."""


def shell_list(text, name):
    """The words of the one line `NAME="..."`; any other assignment refuses."""
    pattern = ASSIGN.format(re.escape(name))
    assigned = [line for line in text.splitlines() if re.match(pattern, line)]
    if len(assigned) != 1:
        raise InputError(f"{len(assigned)} assignments of {name}, not exactly 1")
    match = re.fullmatch(re.escape(name) + r'="([^"$`\\]*)"', assigned[0])
    if not match:
        raise InputError(f'{name} is not assigned as {name}="...": {assigned[0]}')
    words = match.group(1).split()
    if not words:
        raise InputError(f"{name} is empty")
    return words


def split(token):
    """`package/feature` as a (package, feature) pair."""
    package, slash, feature = token.partition("/")
    if not slash or not package or not feature or "/" in feature:
        raise InputError(f"`{token}` is not package/feature")
    return package, feature


def metadata(features):
    """cargo metadata for the whole workspace, resolved with `features` or none."""
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--manifest-path",
        str(ROOT / "Cargo.toml"),
    ]
    if features is not None:
        command += ["--features", " ".join(features)]
    try:
        done = subprocess.run(
            command, capture_output=True, text=True, timeout=300, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InputError(f"cargo metadata did not run: {error}") from error
    if done.returncode != 0:
        raise InputError(
            f"cargo metadata exited {done.returncode}: {done.stderr.strip()}"
        )
    return json.loads(done.stdout)


def resolved(data):
    """Every (package, feature) the resolve enables on a workspace member."""
    members = set(data["workspace_members"])
    names = {package["id"]: package["name"] for package in data["packages"]}
    return {
        (names[node["id"]], feature)
        for node in data["resolve"]["nodes"]
        if node["id"] in members
        for feature in node["features"]
    }


def check():
    text = SOURCE.read_text()
    exceptions = [split(token) for token in shell_list(text, "STABLE_FEATURE_EXCEPTIONS")]
    lists = {name: shell_list(text, name) for name in LISTS}
    for tokens in lists.values():
        for token in tokens:
            split(token)
    baseline = metadata(None)
    members = set(baseline["workspace_members"])
    declared = {
        (package["name"], feature)
        for package in baseline["packages"]
        if package["id"] in members
        for feature in package["features"]
    }
    for package, feature in exceptions:
        if (package, feature) not in declared:
            raise InputError(f"exception {package}/{feature} is not declared")
    always_on = resolved(baseline)
    refusals = []
    for name, tokens in lists.items():
        enabled = resolved(metadata(tokens))
        for exception in exceptions:
            if exception in enabled:
                if exception in always_on:
                    cause = "always on (a default or a non-optional dependency request)"
                else:
                    cause = f"enabled by {name}"
                refusals.append(f"{name}: {'/'.join(exception)} is on: {cause}")
    print(
        f"check-stable-exceptions: {len(exceptions)} exception(s), "
        f"{len(lists)} list(s), {len(refusals)} refusal(s)"
    )
    for refusal in refusals:
        print(f"check-stable-exceptions: REFUSED: {refusal}", file=sys.stderr)
    return 1 if refusals else 0


def main():
    try:
        return check()
    except Exception as error:  # every failure to establish the verdict fails closed
        print(
            f"check-stable-exceptions: CANNOT CHECK: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
