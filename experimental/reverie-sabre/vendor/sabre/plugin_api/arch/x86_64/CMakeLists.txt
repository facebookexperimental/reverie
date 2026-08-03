# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: MIT

sabre_add_component(plugin_api vfork_syscall.s vfork_return_from_child.s
                               clone3_syscall.s clone_syscall.s real_syscall.s)
