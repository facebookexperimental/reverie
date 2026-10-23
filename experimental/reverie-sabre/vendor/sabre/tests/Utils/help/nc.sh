# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: nc
# RUN: %{sbr} %{sbr-id} -- %{nc}           -h     &>%t1
# RUN: grep "nc" %t1
