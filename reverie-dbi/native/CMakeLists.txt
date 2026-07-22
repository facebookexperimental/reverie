cmake_minimum_required(VERSION 3.14)
project(reverie_dbi_client C)

if(NOT DEFINED DynamoRIO_DIR AND DEFINED ENV{DYNAMORIO_HOME})
  if(EXISTS "$ENV{DYNAMORIO_HOME}/install/cmake/DynamoRIOConfig.cmake")
    set(DynamoRIO_DIR "$ENV{DYNAMORIO_HOME}/install/cmake")
  else()
    set(DynamoRIO_DIR "$ENV{DYNAMORIO_HOME}/build/cmake")
  endif()
endif()

find_package(DynamoRIO REQUIRED)

if(NOT DEFINED REVERIE_DBI_RUNTIME)
  message(FATAL_ERROR "Set REVERIE_DBI_RUNTIME to libreverie_dbi.so")
endif()

add_library(reverie_dbi_client SHARED client.c)
configure_DynamoRIO_client(reverie_dbi_client)
use_DynamoRIO_extension(reverie_dbi_client drmgr)
use_DynamoRIO_extension(reverie_dbi_client drreg)
use_DynamoRIO_extension(reverie_dbi_client drx)
target_link_libraries(reverie_dbi_client "${REVERIE_DBI_RUNTIME}")

get_filename_component(runtime_dir "${REVERIE_DBI_RUNTIME}" DIRECTORY)
set_target_properties(
  reverie_dbi_client
  PROPERTIES SKIP_BUILD_RPATH OFF
             BUILD_RPATH "${runtime_dir}")
