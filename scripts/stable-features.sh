#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# The stable feature set: every workspace Cargo feature except the three
# `nightly` features (reverie-ptrace, reverie-process, reverie-test-support),
# which need a nightly compiler by design and run in the nightly CI lane
# (.github/workflows/nightly.yml, --all-features). Sourced by validate.sh,
# scripts/run-percrate-tests.sh, ci.yml, and guide.yml so the lists cannot
# drift. Regenerate from `cargo metadata --no-deps` when features change:
# every workspace feature except `default` and `nightly`, as `package/feature`.
# shellcheck shell=bash

STABLE_FEATURES="reverie-core/perf-fixture reverie-inguest/allocator-fixture reverie-inguest/coordinator-rpc reverie-inguest/exec-native-injection reverie-inguest/exec-private-init reverie-inguest/exec-private-successor reverie-inguest/exec-stop reverie-inguest/fixed-syscall-gates reverie-inguest/launcher reverie-inguest/loader-private-runtime reverie-inguest/native-entry-observer reverie-inguest/native-exec-state reverie-inguest/native-exec-state-fixture reverie-inguest/preload-constructor reverie-inguest/rcb-clock reverie-inguest/rpc-io-fixture reverie-inguest/stage1a-probe reverie-rpc-transport/test-guest-log safeptrace/memory safeptrace/notifier safeptrace/reverie-memory reverie-examples/conformance-tools reverie-examples/host reverie-examples/runtime reverie-examples/test-support reverie-kvm/native-test-support reverie-kvm-core/native-test-support reverie-kvm-core/test-support reverie-linuxemu/native-test-support reverie-linuxemu/test-support reverie-ptrace/rcb-observation reverie-liteinst/allocator-fixture reverie-liteinst/exec-native-injection reverie-liteinst/exec-private-init reverie-liteinst/exec-private-successor reverie-liteinst/fixed-syscall-gates reverie-liteinst/loader-private-runtime reverie-liteinst/native-exec-state reverie-liteinst/preload-constructor reverie-liteinst/rpc-io-fixture reverie-liteinst-preload/allocator-fixture"

# The same list minus the crates ci.yml's regular job excludes; Cargo
# refuses features naming packages outside the selected set.
STABLE_FEATURES_REGULAR="reverie-core/perf-fixture reverie-rpc-transport/test-guest-log safeptrace/memory safeptrace/notifier safeptrace/reverie-memory reverie-examples/conformance-tools reverie-examples/host reverie-examples/runtime reverie-examples/test-support reverie-ptrace/rcb-observation reverie-liteinst/allocator-fixture reverie-liteinst/exec-native-injection reverie-liteinst/exec-private-init reverie-liteinst/exec-private-successor reverie-liteinst/fixed-syscall-gates reverie-liteinst/loader-private-runtime reverie-liteinst/native-exec-state reverie-liteinst/preload-constructor reverie-liteinst/rpc-io-fixture reverie-liteinst-preload/allocator-fixture"
