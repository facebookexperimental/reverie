# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: setfacl
# RUN: %{sbr} %{sbr-id} -- %{setfacl}      --help &>%t1
# RUN: grep "setfacl" %t1
