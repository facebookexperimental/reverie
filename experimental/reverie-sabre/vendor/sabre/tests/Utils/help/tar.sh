# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: tar
# RUN: %{sbr} %{sbr-id} -- %{tar}          --help &>%t1
# RUN: grep "tar" %t1
