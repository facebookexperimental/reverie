#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# The stable feature set: every workspace Cargo feature except the EXCEPTIONS
# at the end of this file and the three `nightly` features (reverie-ptrace,
# reverie-process, reverie-test-support), which need a nightly compiler by
# design and run in the nightly CI lane (.github/workflows/nightly.yml,
# --all-features). Sourced by validate.sh, scripts/run-percrate-tests.sh,
# ci.yml and guide.yml so the lists cannot drift. Regenerate it from
# `cargo metadata --no-deps` when features change: every workspace feature
# except `default` and `nightly`, as `package/feature`, in cargo metadata's
# order, minus STABLE_FEATURE_EXCEPTIONS (scripts/check-stable-exceptions.py
# refuses a list whose resolved build would enable one, by cargo's resolver).
# shellcheck shell=bash

STABLE_FEATURES="reverie-core/perf-fixture reverie-inguest/allocator-fixture reverie-inguest/coordinator-rpc reverie-inguest/exec-native-injection reverie-inguest/exec-private-init reverie-inguest/exec-private-successor reverie-inguest/exec-stop reverie-inguest/exec-stop-producer reverie-inguest/fixed-syscall-gates reverie-inguest/launcher reverie-inguest/loader-private-runtime reverie-inguest/native-entry-observer reverie-inguest/native-exec-state reverie-inguest/native-exec-state-fixture reverie-inguest/preload-constructor reverie-inguest/rcb-clock reverie-inguest/rpc-io-fixture reverie-inguest/stage1a-probe reverie-inguest/test-thread-admission reverie-rpc-transport/test-guest-log safeptrace/memory safeptrace/notifier safeptrace/reverie-memory reverie-examples/conformance-tools reverie-examples/host reverie-examples/runtime reverie-examples/test-support reverie-kvm/native-test-support reverie-kvm-core/native-test-support reverie-kvm-core/test-support reverie-linuxemu/broker-metadata-skip reverie-linuxemu/native-test-support reverie-linuxemu/test-support reverie-ptrace/rcb-observation reverie-liteinst/allocator-fixture reverie-liteinst/exec-native-injection reverie-liteinst/exec-private-init reverie-liteinst/exec-private-successor reverie-liteinst/fixed-syscall-gates reverie-liteinst/liteinst reverie-liteinst/loader-private-runtime reverie-liteinst/native-exec-state reverie-liteinst/preload-constructor reverie-liteinst/rpc-io-fixture reverie-liteinst-preload/allocator-fixture reverie-liteinst-preload/liteinst"

# The same list minus the crates ci.yml's regular job excludes; Cargo
# refuses features naming packages outside the selected set.
STABLE_FEATURES_REGULAR="reverie-core/perf-fixture reverie-rpc-transport/test-guest-log safeptrace/memory safeptrace/notifier safeptrace/reverie-memory reverie-examples/conformance-tools reverie-examples/host reverie-examples/runtime reverie-examples/test-support reverie-ptrace/rcb-observation reverie-liteinst/allocator-fixture reverie-liteinst/exec-native-injection reverie-liteinst/exec-private-init reverie-liteinst/exec-private-successor reverie-liteinst/fixed-syscall-gates reverie-liteinst/loader-private-runtime reverie-liteinst/native-exec-state reverie-liteinst/preload-constructor reverie-liteinst/rpc-io-fixture reverie-liteinst-preload/allocator-fixture"

# EXCEPTIONS: workspace features that no build with a list above may enable,
# by any path cargo resolves (defaults and dependency requests included):
# - reverie-inguest/private-libc-exports: it exports the private image's libc
#   symbols, only a private image's own build may enable it, and on GNU it
#   compiles nothing.
# - reverie-kvm/broker-metadata-skip: declared never-enabled, and at this
#   revision no code reads it (reverie-kvm/Cargo.toml:17-19).
# - reverie-liteinst/aarch64-trap-and-patch-test: a test-only selector; on
#   aarch64 it replaces the production explicit-patch refusal test
#   (reverie-liteinst/src/lib.rs:684-740).
STABLE_FEATURE_EXCEPTIONS="reverie-inguest/private-libc-exports reverie-kvm/broker-metadata-skip reverie-liteinst/aarch64-trap-and-patch-test"
# scripts/check-stable-exceptions.py reads this list; the shell's one use of
# it is this guard, which fails only if the list is unset.
: "${STABLE_FEATURE_EXCEPTIONS?}"
