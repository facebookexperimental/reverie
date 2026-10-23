# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: ls
# RUN: %{sbr} %{sbr-id} -- %{ls}           --help &>%t1
# RUN: grep "ls" %t1
