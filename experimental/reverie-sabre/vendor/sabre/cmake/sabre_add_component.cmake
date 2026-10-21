function(sabre_add_component target_name)
  add_library(${target_name} STATIC ${ARGN})
  target_include_directories(${target_name}
                             PUBLIC ${SABRE_COMPONENT_INCLUDE_DIRS})
  target_compile_definitions(${target_name} PUBLIC ${SABRE_COMPONENT_C_DEFINES})
  target_compile_options(${target_name} PRIVATE ${SABRE_COMPONENT_C_FLAGS})
endfunction()

function(sabre_add_executable exe_name)
  add_executable(${exe_name} ${ARGN})
  target_compile_definitions(${exe_name} PRIVATE ${SABRE_COMPONENT_C_DEFINES})
  target_compile_options(${exe_name} PRIVATE ${SABRE_COMPONENT_C_FLAGS})
  if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    string(REPLACE ";" " " SABRE_EXE_LINK_FLAGS_STR "${SABRE_EXE_LINK_FLAGS}")
    set_property(
      TARGET ${exe_name}
      APPEND
      PROPERTY LINK_FLAGS ${SABRE_EXE_LINK_FLAGS_STR})
  else()
    target_link_options(${exe_name} PRIVATE ${SABRE_EXE_LINK_FLAGS})
  endif()
  target_link_libraries(${exe_name} loader)
endfunction()

function(sabre_add_plugin plugin_name)
  add_library(${plugin_name} MODULE ${PROTECTOR} ${ARGN})
  target_include_directories(${plugin_name} PUBLIC ${SABRE_PLUGIN_INCLUDE_DIRS})
  target_compile_definitions(${plugin_name} PUBLIC ${SABRE_PLUGIN_C_DEFINES})
  target_compile_options(${plugin_name} PUBLIC ${SABRE_PLUGIN_C_FLAGS})
  target_link_libraries(${plugin_name} plugin_api backend)
endfunction()
