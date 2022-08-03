add_library("bpfverifier_common_settings" INTERFACE)
target_compile_options("bpfverifier_common_settings" INTERFACE
  -fvisibility=hidden
)

set_target_properties("bpfverifier_common_settings" PROPERTIES
  INTERFACE_POSITION_INDEPENDENT_CODE
    true
)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  target_compile_options("bpfverifier_common_settings" INTERFACE
    -O0
  )

  target_compile_definitions("bpfverifier_common_settings" INTERFACE
    DEBUG
  )

else()
  target_compile_options("bpfverifier_common_settings" INTERFACE
    -O2
  )

  target_compile_definitions("bpfverifier_common_settings" INTERFACE
    NDEBUG
  )
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR
   "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")

  target_compile_options("bpfverifier_common_settings" INTERFACE
    -g3
  )

else()
  target_compile_options("bpfverifier_common_settings" INTERFACE
    -g0
  )
endif()
