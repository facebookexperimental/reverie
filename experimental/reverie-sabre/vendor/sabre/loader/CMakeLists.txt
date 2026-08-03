# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

list(APPEND SABRE_COMPONENT_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/includes/loader)

# Build library
sabre_add_component(
  loader
  backend_stats.c
  elf_loading.c
  ld_sc_handler.c
  loader.c
  maps.c
  premain.c
  rewriter.c
  debuginfo.c)

target_link_libraries(loader ${CMAKE_DL_LIBS} backend elf plugin_api)

add_subdirectory(tools)
