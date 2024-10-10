#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Dumps VDSO to the given file. This is useful for debugging why Reverie might not
be able to patch VDSO entries.

Usage: ./dump-vdso.py [filename]

Examples:
  ./dump-vdso.py | hexdump -C
  ./dump-vdso.py vdso.so && objdump -d vdso.so
"""

import argparse
import ctypes
import sys
from typing import List, Optional


def dump_vdso() -> list[ctypes.c_ubyte] | None:
    """
    Returns a list containing the VDSO.
    """
    with open("/proc/self/maps") as f:
        for line in f:
            if "[vdso]" in line:
                start, end = (int(x, 16) for x in line.split(" ")[0].split("-"))
                length = end - start
                return (ctypes.c_ubyte * length).from_address(start)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="dump-vdso", description="Dumps VDSO to the given file."
    )
    parser.add_argument("filename", nargs="?", help="Filename to write to.")

    args = parser.parse_args()

    data = dump_vdso()

    if args.filename:
        with open(args.filename, "wb") as f:
            f.write(data)
    else:
        sys.stdout.buffer.write(data)

    return 0


if __name__ == "__main__":
    main()
