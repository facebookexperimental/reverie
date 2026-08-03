# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: bunzip2
# RUN: %{sbr} %{sbr-id} -- %{bunzip2}      --help &>%t1
# RUN: grep "bunzip2" %t1
