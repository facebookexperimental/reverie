#!/bin/bash

set -e

MUSL_VER=1.2.1
MUSL_SOURCE_WORK_DIR=$(mktemp -d)
MUSL_BUILD_DIR=""

trap cleanup EXIT

function cleanup {
    echo "cleanup.." && rm -fr "${MUSL_SOURCE_WORK_DIR}"
}

function prepare {
    mkdir -p "${MUSL_SOURCE_WORK_DIR}" && cd "${MUSL_SOURCE_WORK_DIR}"
    curl -L $(fwdproxy-config curl) "https://git.musl-libc.org/cgit/musl/snapshot/musl-${MUSL_VER}.tar.gz" | tar -zxf -
    mkdir -p "musl-${MUSL_VER}-build" && cd "musl-${MUSL_VER}-build"
    MUSL_BUILD_DIR=$(pwd)
}

function build {
    if [ "${MUSL_BUILD_DIR}" != "" ]; then
        cd "${MUSL_BUILD_DIR}"
        ../musl-${MUSL_VER}/configure --prefix=""
        make -j
    fi
}

prepare && build
