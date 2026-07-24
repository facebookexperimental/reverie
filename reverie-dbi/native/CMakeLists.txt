cmake_minimum_required(VERSION 3.14)
project(reverie_dbi_client C)

if(NOT DEFINED DynamoRIO_DIR)
  message(FATAL_ERROR "DynamoRIO_DIR must point to Cargo's vendored install")
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
use_DynamoRIO_extension(reverie_dbi_client drwrap)
target_link_libraries(reverie_dbi_client "${REVERIE_DBI_RUNTIME}")

get_filename_component(runtime_dir "${REVERIE_DBI_RUNTIME}" DIRECTORY)
set_target_properties(
  reverie_dbi_client
  PROPERTIES SKIP_BUILD_RPATH OFF
             BUILD_RPATH "${runtime_dir}")
