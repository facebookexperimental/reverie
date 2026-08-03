# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: dbus-uuidgen
# RUN: %{sbr} %{sbr-id} -- %{dbus-uuidgen} --help &>%t1
# RUN: grep "dbus-uuidgen" %t1
