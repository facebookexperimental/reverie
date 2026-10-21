# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: ps
# RUN: %{sbr} %{sbr-id} -- %{ps}           --help s &>%t1
# RUN: grep "ps" %t1
