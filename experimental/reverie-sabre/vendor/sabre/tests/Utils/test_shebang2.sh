#!/usr/bin/env bash

# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# RUN: %{sbr} %{sbr-id} -- %s &>%t1.actual
# RUN: echo "Hello World!" >%t1.expected
# RUN: diff %t1.actual %t1.expected

echo "Hello World!"
