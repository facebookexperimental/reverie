cmake_minimum_required(VERSION 3.14)
project(reverie_dbt_client C)

if(NOT DEFINED DynamoRIO_DIR)
  message(FATAL_ERROR "DynamoRIO_DIR must point to Cargo's vendored install")
endif()
find_package(DynamoRIO REQUIRED)

if(NOT DEFINED REVERIE_DBT_RUNTIME)
  message(FATAL_ERROR "Set REVERIE_DBT_RUNTIME to libreverie_dbt.so")
endif()

add_library(reverie_dbt_client SHARED client.c)
configure_DynamoRIO_client(reverie_dbt_client)

# DynamoRIO's private x86 loader does not implement R_X86_64_TLSDESC.
# Match Hermit's installed-client producer when GNU defaults to GNU2 TLS.
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  target_compile_options(reverie_dbt_client PRIVATE -mtls-dialect=gnu)
endif()
use_DynamoRIO_extension(reverie_dbt_client drmgr)
use_DynamoRIO_extension(reverie_dbt_client drreg)
use_DynamoRIO_extension(reverie_dbt_client drx)
use_DynamoRIO_extension(reverie_dbt_client drwrap)
target_link_libraries(reverie_dbt_client "${REVERIE_DBT_RUNTIME}")

get_filename_component(runtime_dir "${REVERIE_DBT_RUNTIME}" DIRECTORY)
set_target_properties(
  reverie_dbt_client
  PROPERTIES SKIP_BUILD_RPATH OFF
             BUILD_RPATH "${runtime_dir}")
