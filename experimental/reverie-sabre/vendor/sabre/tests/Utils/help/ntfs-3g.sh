# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: ntfs-3g
# RUN: %{sbr} %{sbr-id} -- %{ntfs-3g} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 9
# RUN: grep "Usage:    ntfs-3g" %t1
