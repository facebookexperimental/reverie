# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: gzip
# RUN: %{sbr} %{sbr-id} -- %{gzip}         --help &>%t1
# RUN: grep "gzip" %t1
