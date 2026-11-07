# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: chacl
# RUN: %{sbr} %{sbr-id} -- %{chacl} &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "chacl" %t1
