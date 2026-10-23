# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# These tests are for testing the existence of: unlinkat, faccessat and
# newfstatat system call.
#
# RUN: echo > %t1.file
# RUN: echo > %t2.file
# RUN: mkdir -p %t3.dir
# RUN: %{sbr} %{sbr-id} -- /bin/rm %t1.file
# RUN: %{sbr} %{sbr-id} -- /bin/rm -f %t2.file
# RUN: %{sbr} %{sbr-id} -- /bin/rm -rf %t3.dir
