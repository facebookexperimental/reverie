#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

set -eu

if [ "${REVERIE_DBT_TEST_DRRUN_STDERR+x}" = x ]; then
  printf '%s' "$REVERIE_DBT_TEST_DRRUN_STDERR" >&2
fi
if [ "${REVERIE_DBT_TEST_DRRUN_DIAGNOSTIC+x}" = x ]; then
  printf '%s' "$REVERIE_DBT_TEST_DRRUN_DIAGNOSTIC" >&198
fi

while [ "$1" != -- ]; do
  shift
done
shift
exec "$@"
