# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: ip
# RUN: %{sbr} %{sbr-id} -- %{ip} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 255
# RUN: grep "ip" %t1
