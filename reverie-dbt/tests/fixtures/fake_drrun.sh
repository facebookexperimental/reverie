#!/bin/bash
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
