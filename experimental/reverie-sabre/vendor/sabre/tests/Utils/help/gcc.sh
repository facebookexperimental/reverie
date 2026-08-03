# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# RUN: %{sbr} %{sbr-id} -- %{gcc} --help &>%t1
# RUN: grep "gcc" %t1
