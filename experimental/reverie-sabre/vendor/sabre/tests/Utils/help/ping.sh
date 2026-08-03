# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: ping
# RUN: %{ping} || RC_ORIG=$(echo $?)
# RUN: %{sbr} %{sbr-id} -- %{ping} &>%t1 || RC_SABRE=$(echo $?)
# RUN: test ${RC_ORIG} -eq ${RC_SABRE}
# RUN: grep "ping" %t1
