set(src_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

# TODO: To be filled; remove the EXCLUDE_FROM_ALL when done
set("target_placeholder_source_list"
  ${src_root}/kernel/bpf/core.c
)

add_library("target_placeholder" EXCLUDE_FROM_ALL
  ${target_placeholder_source_list}
)

target_link_libraries("target_placeholder" PRIVATE
  "bpfverifier_common_settings"
)

target_compile_definitions("target_placeholder" PRIVATE
  "TEST=1"
)

# Submodule manager
find_package(Git REQUIRED)

set(linux_version_file "${CMAKE_CURRENT_BINARY_DIR}/linux_version.txt")
set(linux_root_makefile "${CMAKE_CURRENT_SOURCE_DIR}/src/Makefile")

set(BPFVERIFIER_PREVIOUS_LINUX_VERSION "" CACHE STRING "The previouly cloned Linux version (internal, do not set)")
if(NOT "${BPFVERIFIER_PREVIOUS_LINUX_VERSION}" STREQUAL "${BPFVERIFIER_LINUX_VERSION}")
  message(STATUS "bpfverifier: The selected linux version has been changed")
  file(REMOVE "${linux_version_file}")

  set(BPFVERIFIER_PREVIOUS_LINUX_VERSION "${BPFVERIFIER_LINUX_VERSION}")
endif()

add_custom_command(
  OUTPUT "${linux_version_file}" ${target_placeholder_source_list}
  COMMENT "bpfverifier: Updating the Linux kernel submodule"

  COMMAND "${GIT_EXECUTABLE}" fetch --tags
  COMMAND "${GIT_EXECUTABLE}" checkout -f "${BPFVERIFIER_LINUX_VERSION}"
  COMMAND "${GIT_EXECUTABLE}" describe --tags > "${linux_version_file}.temp"
  COMMAND "${CMAKE_COMMAND}" "-DEXPECTED_VERSION:STRING=${BPFVERIFIER_LINUX_VERSION}" "-DVERSION_FILE:PATH=${linux_version_file}.temp" -P "${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_version.cmake"
  COMMAND "${CMAKE_COMMAND}" -E rename "${linux_version_file}.temp" "${linux_version_file}"

  DEPENDS "linux_submodule_initializer"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src"
  VERBATIM
  
)

add_custom_target("linux_submodule_updater" DEPENDS
  "${linux_version_file}"
)

add_custom_command(
  OUTPUT "${linux_root_makefile}"
  COMMENT "bpfverifier: Initializing the linux kernel submodule"

  COMMAND "${GIT_EXECUTABLE}" submodule update --init "src"

  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  VERBATIM
)

add_custom_target("linux_submodule_initializer" DEPENDS
  "${linux_root_makefile}"
)
