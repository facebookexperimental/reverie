sabre_add_executable(process-vdso process-vdso.c)
sabre_add_executable(dump-vdso    dump-vdso.c)

target_include_directories(process-vdso PRIVATE ${CMAKE_SOURCE_DIR}/includes/arch)
target_include_directories(dump-vdso PRIVATE ./includes)

target_compile_options(dump-vdso PRIVATE ${SABRE_COMPONENT_C_FLAGS} "-Wno-unused-parameter")
target_compile_options(process-vdso PRIVATE ${SABRE_COMPONENT_C_FLAGS} "-Wno-unused-parameter")

set_target_properties(dump-vdso PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools)
set_target_properties(process-vdso PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools)

target_link_libraries(process-vdso loader)
target_link_libraries(dump-vdso    loader)
