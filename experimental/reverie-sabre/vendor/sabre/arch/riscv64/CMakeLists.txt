# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

list(APPEND SABRE_COMPONENT_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/includes/arch")

sabre_add_component(backend
  clone_syscall.c
  handle_syscall.s
  handle_syscall_loader.s
  handle_vdso.s
  rewriter.c
  riscv_decoder.c
  riscv_utils.c
  syscall_stackframe.c
)

sabre_add_component(realsyscall
  clone_syscall.c
  real_syscall.s)

target_link_libraries(backend loader)

sabre_add_executable(sabre main.s)
set_target_properties(sabre PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
